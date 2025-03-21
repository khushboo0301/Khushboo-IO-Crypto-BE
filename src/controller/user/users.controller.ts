import {
  Body,
  Controller,
  Get,
  HttpStatus,
  Post,
  Put,
  Res,
  Req,
  Query,
  UseInterceptors,
  UploadedFile,
  UploadedFiles,
} from "@nestjs/common";
import { CreateUserDto } from "src/dto/create-users.dto";
import { UpdateUserProfileDto } from "src/dto/update-users-profile.dto";
import { UserService } from "src/service/user/users.service";
import { EmailService } from "src/service/email/email.service";
import { TokenService } from "src/service/token/token.service";
import { AnyFilesInterceptor, FileInterceptor } from "@nestjs/platform-express";
import { Express } from "express";
import { ConfigService } from "@nestjs/config";
import { UpdateAccountSettingsDto } from "src/dto/update-account-settings.dto";
import { UpdateKycDataDto } from "src/dto/update-kyc.dto";
import { SkipThrottle } from "@nestjs/throttler";
import moment from "moment";
import { InjectModel } from "@nestjs/mongoose";
import { NotFoundException } from "@nestjs/common";
import { Model } from "mongoose";
import { IUser } from "src/interface/users.interface";
import { countries, countryCodes } from 'src/countries';
const rp = require("request-promise-native");
const speakeasy = require("speakeasy");
const jwt = require("jsonwebtoken");
const Web3 = require("web3");
const web3 = new Web3("https://cloudflare-eth.com/");

const getSignMessage = (address, nonce) => {
  return `Please sign this message for address ${address}:\n\n${nonce}`;
};

@SkipThrottle()
@Controller("users")
export class UsersController {
  constructor(
    private readonly userService: UserService,
    private readonly emailService: EmailService,
    private readonly tokenService: TokenService,
    private readonly configService: ConfigService,
    @InjectModel("user") private usersModel: Model<IUser>
  ) {}

  /**
   * This API endpoint verifies the authenticity of a user's identity based on the provided signature.
   * @param req
   * @param response
   * @param body
   * @param query
   * @returns
   */
  @SkipThrottle(false)
  @Post("/verify")
  async verify(
    @Req() req: any,
    @Res() response,
    @Body() body: { walletType: string; referredBy?: string },
    @Query() query: { signatureId: string }
  ) {
    try {
      const jwtSecret = this.configService.get("jwt_secret");
      const authHeader = req.headers["authorization"];
      const tempToken = authHeader?.split(" ")[1];
      if (!tempToken) {
        return response.sendStatus(HttpStatus.FORBIDDEN);
      }
      const { authData } = req.body;
      const {
        nonce,
        address: rawAddress,
        verifiedAddress: altAddress,
      } = authData;
      const address = rawAddress || altAddress;
      const { walletType, referredBy = null } = body;
      const s3 = this.configService.get("s3");
      const bucketName = this.configService.get("aws_s3_bucket_name");

      const message = getSignMessage(address, nonce);
      const verifiedAddress = await web3.eth.accounts.recover(
        message,
        query.signatureId
      );

      if (verifiedAddress.toLowerCase() !== address.toLowerCase()) {
        return response
          .status(HttpStatus.BAD_REQUEST)
          .json({ message: "User not valid." });
      }

      const userByAddress = await this.userService.getFindbyAddress(address);

      if (userByAddress?.status === "Suspend") {
        return response
          .status(HttpStatus.BAD_REQUEST)
          .json({ message: "Can't Login, You are Suspended by Admin." });
      }

      const token = jwt.sign({ verifiedAddress, nonce }, jwtSecret, {
        expiresIn: "1w",
      });
      await this.tokenService.createToken({ token });
      const lastLogin = moment.utc(nonce).format();

      let userInfo;
      let imageUrl = null;

      if (userByAddress) {
        // Update existing user
        const is_2FA_login_verified = !userByAddress.is_2FA_enabled;
        let is_2FA_twilio_login_verified = true;
        if (userByAddress.is_2FA_SMS_enabled) {
          if(userByAddress.phone && userByAddress.phoneCountry) {
            is_2FA_twilio_login_verified = false;
          }
        }
        let UpdateUserProfileDto: any = {
          nonce: nonce,
          _token: token,
          last_login: lastLogin,
          is_2FA_login_verified,
          is_2FA_twilio_login_verified,
        };

        if (userByAddress.profile) {
          imageUrl = s3.getSignedUrl("getObject", {
            Bucket: bucketName,
            Key: userByAddress.profile,
          });
        }

        userInfo = await this.userService.updateUser(
          userByAddress._id,
          UpdateUserProfileDto,
          null,
          bucketName
        );
      } else {
        // Create new user
        let createUserDto: any = {
          wallet_address: address,
          nonce: nonce,
          _token: token,
          wallet_type: walletType,
          referred_by: referredBy,
          last_login: lastLogin,
          created_at: lastLogin,
          is_2FA_login_verified: true,
          is_2FA_twilio_login_verified: true,
        };

        userInfo = await this.userService.createUser(createUserDto);
      }

      // Remove sensitive data before response
      userInfo.google_auth_secret = undefined;

      let encryptedPhone = '';
      if (userInfo?.phone) {
        encryptedPhone = this.emailService.encryptEmail(userInfo.phone);
      }
      return response.status(HttpStatus.OK).json({
        token: token,
        user_id: userInfo._id,
        is_2FA_enabled: userInfo.is_2FA_enabled,
        is_2FA_login_verified: userInfo.is_2FA_login_verified,
        is_2FA_twilio_login_verified: userInfo.is_2FA_twilio_login_verified,
        is_2FA_SMS_enabled: userInfo.is_2FA_SMS_enabled,
        imageUrl: imageUrl ? imageUrl : null,
        isPhoneCode: encryptedPhone || userInfo?.phoneCountry ? true : false,
      });
    } catch (err) {
      return response.status(HttpStatus.BAD_REQUEST).json(err.response);
    }
  }

  /**
   * This API endpoint creates a new user based on the provided user data.
   * @param response
   * @param createUserDto
   * @returns
   */
  @Post()
  async createUsers(@Res() response, @Body() createUserDto: CreateUserDto) {
    try {
      const newUser = await this.userService.createUser(createUserDto);
      return response.status(HttpStatus.CREATED).json({
        message: "User has been created successfully",
        newUser,
      });
    } catch (err) {
      return response.status(HttpStatus.BAD_REQUEST).json({
        statusCode: 400,
        message: "Error: User not created!",
        error: "Bad Request",
      });
    }
  }

  /**
   * This API endpoint updates user profile information including profile picture.
   * @param req
   * @param response
   * @param updateUsersDto
   * @param file
   * @returns
   */
  @Put()
  @UseInterceptors(FileInterceptor("profile"))
  async updateUsers(
    @Req() req: any,
    @Res() response,
    @Body() updateUsersDto: UpdateUserProfileDto,
    @UploadedFile() file: Express.Multer.File
  ) {
    try {
      if (file) {
        const fileValidationError = this.validateFile(file);
        if (fileValidationError) {
          return response.status(HttpStatus.BAD_REQUEST).json({
            message: fileValidationError,
          });
        }
      }

      const nameValidationError = this.validateAliasNames(
        updateUsersDto.fname_alias,
        updateUsersDto.lname_alias
      );
      if (nameValidationError) {
        return response.status(HttpStatus.BAD_REQUEST).json({
          message: nameValidationError,
        });
      }

      if (updateUsersDto.bio && updateUsersDto.bio.length > 80) {
        return response.status(HttpStatus.BAD_REQUEST).json({
          message: "Bio should not exceed 80 characters.",
        });
      }

      if (typeof updateUsersDto.profile === "string") {
        delete updateUsersDto.profile;
        return response.status(HttpStatus.BAD_REQUEST).json({
          message: "Something is wrong with the profile image.",
        });
      }

      const userDetails = await this.userService.getFindbyAddress(
        req.headers.authData.verifiedAddress
      );
      const userId = userDetails._id.toString();
      const bucketName = "middnapp";

      await this.userService.updateUser(userId, updateUsersDto, file, bucketName);

      return response.status(HttpStatus.OK).json({
        message: "User has been successfully updated.",
      });
    } catch (err) {
      return response.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
        message: err.message || "An unexpected error occurred.",
      });
    }
  }

  private validateFile(file: Express.Multer.File): string | null {
    const allowedFileExtensions = ["png", "jpeg", "jpg", "gif"];
    const allowedMimeTypes = ["image/png", "image/jpeg", "image/jpg", "image/gif"];
    const maxFileSizeMb = 2;

    const fileExtension = file.originalname.split(".").pop()?.toLowerCase();
    if (!fileExtension || !allowedFileExtensions.includes(fileExtension)) {
      return "Inappropriate file type.";
    }

    if (!allowedMimeTypes.includes(file.mimetype)) {
      return "Inappropriate file type.";
    }

    if (file.size / (1024 * 1024) > maxFileSizeMb || file.size < 1) {
      return "File size should be between 1 Byte to 2 MB.";
    }

    return null;
  }

  private validateAliasNames(fnameAlias: string, lnameAlias: string): string | null {
    const pattern = /^[a-zA-Z0-9]*$/;
    const maxLength = 20;

    if (!fnameAlias.match(pattern) || fnameAlias.length > maxLength) {
      return "Please enter a valid first name.";
    }

    if (!lnameAlias.match(pattern) || lnameAlias.length > maxLength) {
      return "Please enter a valid last name.";
    }

    return null;
  }

  /**
   * This method handles the updating of KYC (Know Your Customer) information for a user.
   * It receives the updated KYC data, including personal information and document uploads,
   * validates the data, and updates the user's KYC information in the database.
   * @param response
   * @param updateKycDto
   * @param req
   * @param files
   * @returns
   */
  @SkipThrottle(false)
  @Put("/updateKyc")
  @UseInterceptors(AnyFilesInterceptor())
  async updateKyc(
    @Res() response,
    @Body() updateKycDto: UpdateKycDataDto,
    @Req() req: any,
    @UploadedFiles() files?: Array<Express.Multer.File>
  ) {
    try {
      const validationError = this.validateKycData(updateKycDto, files);

      if (validationError) {
        return response.status(HttpStatus.BAD_REQUEST).json({
          message: validationError,
        });
      }

      const userDetails = await this.userService.getFindbyAddress(
        req.headers.authData.verifiedAddress
      );

      if (userDetails.kyc_completed && userDetails.is_verified !== 2) {
        return response.status(HttpStatus.BAD_REQUEST).json({
          message: "KYC is already submitted.",
        });
      }

      const { passport_url, user_photo_url } = this.extractFiles(files);
      this.removeUnnecessaryFields(updateKycDto, userDetails);

      if (updateKycDto.dob && !this.validateDateOfBirth(updateKycDto.dob)) {
        return response.status(HttpStatus.BAD_REQUEST).json({
          message: "Invalid Date Of Birth.",
        });
      }

      const userId = userDetails._id.toString();
      await this.userService.updateKyc(userId, updateKycDto, passport_url, user_photo_url);
      const updatedUser = await this.userService.getUser(userId);

      if (updatedUser && updatedUser?.email && updatedUser?.email_verified) {
        const emailSent = await this.sendKycConfirmationEmail(updatedUser);

        if (emailSent) {
          return response.status(HttpStatus.OK).json({
            message: "User has been successfully updated.",
          });
        } else {
          return response.status(HttpStatus.BAD_REQUEST).json({
            message: "Invalid or expired verification token.",
          });
        }
      }

      return response.status(HttpStatus.OK).json({
        message: "User has been successfully updated.",
      });
    } catch (error) {
      return response.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
        message: error.message || "An unexpected error occurred.",
      });
    }
  }

  private validateKycData(updateKycDto: UpdateKycDataDto, files?: Array<Express.Multer.File>): string | null {
    const requiredFields = [
      "fname",
      "lname",
      "res_address",
      "city",
      "postal_code",
      "country_of_issue",
      "verified_with",
      "dob",
    ];

    for (const field of requiredFields) {
      if (!updateKycDto[field]?.trim()) {
        return `${field.replace(/_/g, " ")} is missing`;
      }
    }

    if (!files || files.length < 2) {
      return "Files are missing";
    }

    const hasUserPhoto = files.some((file) => file.fieldname === "user_photo_url");
    const hasPassportPhoto = files.some((file) => file.fieldname === "passport_url");

    if (!hasUserPhoto) return "User photo is missing";
    if (!hasPassportPhoto) return "Passport photo is missing";

    const postalCodePattern = /^[a-zA-Z0-9]*$/;
    if (!postalCodePattern.test(updateKycDto.postal_code)) {
      return "Postal code is not valid";
    }

    return null;
  }

  private extractFiles(files: Array<Express.Multer.File>) {
    let passport_url = {};
    let user_photo_url = {};

    files.forEach((file) => {
      if (file.fieldname === "passport_url") passport_url = file;
      if (file.fieldname === "user_photo_url") user_photo_url = file;
    });

    return { passport_url, user_photo_url };
  }

  private removeUnnecessaryFields(updateKycDto: UpdateKycDataDto, userDetails: any) {
    const fieldsToCheck = ["fname", "lname", "mname", "dob", "city"];
    fieldsToCheck.forEach((field) => {
      if (userDetails[field] && userDetails[field].trim()) {
        delete updateKycDto[field];
      }
    });

    delete updateKycDto.is_verified;
    delete updateKycDto.wallet_address;
  }

  private validateDateOfBirth(dob: string): boolean {
    if (!moment(dob, "DD/MM/YYYY", true).isValid()) return false;

    const currentDate = moment();
    const parsedDob = moment(dob, "DD/MM/YYYY");

    return !parsedDob.isAfter(currentDate);
  }

  private async sendKycConfirmationEmail(user: any): Promise<boolean> {
    const globalContext = {
      formattedDate: moment().format("dddd, MMMM D, YYYY"),
      greeting: `Hello ${
        user.fname ? `${user.fname} ${user.lname}` : "John Doe"
      }`,
      para1:
        "Thank you for submitting your verification request. We've received your submitted document and other information for identity verification.",
      para2:
        "We'll review your information and if all is in order will approve your identity. If the information is incorrect or something missing, we will request this as soon as possible.",
      title: "KYC Submitted Email",
    };

    const mailSubject = `[Middn.io] :: Document Submitted for Identity Verification - https://ico.middn.com/`;
    return this.emailService.sendVerificationEmail(user, globalContext, mailSubject);
  }

  /**
   * This method validates the file type and size of an uploaded file.
   * It checks if the uploaded file has a valid file extension and size,
   * and returns an appropriate response message accordingly.
   * @param response
   * @param file
   * @returns
   */
  @Post("/validate-file-type")
  @UseInterceptors(AnyFilesInterceptor())
  async validateFileType(
    @Res() response,
    @UploadedFiles() file: Express.Multer.File
  ) {
    try {
      // Array of allowed files
      const array_of_allowed_files = ["jpg", "jpeg", "png"];
      // Allowed file size in mb
      const allowed_file_size = 5;
      // Get the extension of the uploaded file
      if (file) {
        const file_extension = file[0].originalname.slice(
          ((file[0].originalname.lastIndexOf(".") - 1) >>> 0) + 2
        );
        // Check if the uploaded file is allowed
        if (!array_of_allowed_files.includes(file_extension)) {
          return response
            .status(HttpStatus.BAD_REQUEST)
            .json({ message: "Please upload Valid Image" });
        }
        if (
          file[0].size / (1024 * 1024) > allowed_file_size ||
          file[0].size < 10240
        ) {
          return response.status(HttpStatus.BAD_REQUEST).json({
            message: "File size should come between 10 KB to 5120 KB",
          });
        }
        return response
          .status(HttpStatus.OK)
          .json({ message: "File uploaded successfully." });
      }
    } catch (err) {
      return response.status(HttpStatus.BAD_REQUEST).json(err.response);
    }
  }

  /**
   * * This method updates the account settings of a user.
   * @param req
   * @param response
   * @param updateAccountSettingDto
   * @returns
   */
  @SkipThrottle(false)
  @Put("/updateAccountSettings")
  async updateAccountSettings(
    @Req() req: any,
    @Res() response,
    @Body() updateAccountSettingDto: UpdateAccountSettingsDto
  ) {
    try {
      const userDetails = await this.userService.getFindbyAddress(
        req.headers.authData.verifiedAddress
      );
      const userId = userDetails._id.toString();

      // Trim input fields
      const fieldsToTrim = [
        "fname",
        "lname",
        "email",
        "phone",
        "city",
        "phoneCountry",
        "dob",
      ];
      fieldsToTrim.forEach(
        (field) =>
          updateAccountSettingDto[field] &&
          (updateAccountSettingDto[field] = updateAccountSettingDto[field].trim())
      );

      // Check for missing fields
      const requiredFields = [
        { field: "fname", message: "First Name is missing." },
        { field: "lname", message: "Last Name is missing." },
        { field: "email", message: "Email is missing." },
        { field: "phone", message: "Phone is missing." },
        { field: "city", message: "City is missing." },
        { field: "phoneCountry", message: "Phone Country is missing." },
        { field: "dob", message: "Date of Birth is missing." },
      ];
      for (const { field, message } of requiredFields) {
        if (!updateAccountSettingDto[field]) {
          return response.status(HttpStatus.BAD_REQUEST).json({ message });
        }
      }

      // Retain existing data for fields already set
      ["fname", "lname", "location", "dob"].forEach((field) => {
        if (userDetails[field]) delete updateAccountSettingDto[field];
      });

      // Validate fields
      if (
        updateAccountSettingDto.phone &&
        !/^[0-9]{5,10}$/.test(updateAccountSettingDto.phone)
      ) {
        return response
          .status(HttpStatus.BAD_REQUEST)
          .json({ message: "Invalid Phone." });
      }

      const isValidEmail = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/.test(
        updateAccountSettingDto.email
      );
      if (updateAccountSettingDto.email && !isValidEmail) {
        return response
          .status(HttpStatus.BAD_REQUEST)
          .json({ message: "Invalid E-mail address." });
      }

      if (
        updateAccountSettingDto.location &&
        !countries.includes(updateAccountSettingDto.location)
      ) {
        return response
          .status(HttpStatus.BAD_REQUEST)
          .json({ message: "Invalid country name." });
      }

      if (
        updateAccountSettingDto.phoneCountry &&
        !countryCodes.includes(updateAccountSettingDto.phoneCountry)
      ) {
        return response
          .status(HttpStatus.BAD_REQUEST)
          .json({ message: "Invalid country code." });
      }

      if (
        updateAccountSettingDto.dob &&
        !moment(updateAccountSettingDto.dob, "DD/MM/YYYY", true).isValid()
      ) {
        return response
          .status(HttpStatus.BAD_REQUEST)
          .json({ message: "Invalid Date Of Birth." });
      }

      // Email validation: uniqueness and verification checks
      if (updateAccountSettingDto.email) {
        const emailCheck = await this.checkEmailAvailability(
          updateAccountSettingDto.email,
          userId
        );
        if (emailCheck) return response.status(emailCheck.status).json(emailCheck.body);
      }

      // Update user details
      await this.userService.updateAccountSettings(userId, updateAccountSettingDto);
      const updatedUser = await this.userService.getUser(userId);
 
      // Send email verification if email is updated and not verified
      if ( updatedUser &&
        updatedUser?.email &&
        (!updatedUser?.email_verified || updatedUser?.email_verified === undefined)
      ) {
        const emailStatus = await this.sendEmailVerification(updatedUser, userId);
        if (emailStatus)
          return response.status(emailStatus.status).json(emailStatus.body);
      }

      return response
        .status(HttpStatus.OK)
        .json({ message: "User has been successfully updated" });
    } catch (error) {
      return response.status(HttpStatus.BAD_REQUEST).json(error.response);
    }
  }

  // Utility: Check email availability
  private async checkEmailAvailability(email: string, userId: string) {
    try {
      const userEmail = await this.userService.getFindbyEmail(email);
      if (userEmail && userEmail._id && userEmail._id.toString() !== userId) {
        return { status: HttpStatus.BAD_REQUEST, body: { message: "Email already exists." } };
      }
      const userEmailCheck = await this.userService.getFindbyId(userId);
      
      if (userEmailCheck &&
        userEmailCheck?.email_verified &&
        userEmailCheck.email !== email
      ) {
        return {
          status: HttpStatus.BAD_REQUEST,
          body: { message: "Your email address is already verified and cannot be changed." },
        };
      }
    } catch (error) {
      console.error("Error while checking email existence: ", error);
      return { status: HttpStatus.INTERNAL_SERVER_ERROR, body: { message: "Error processing request." } };
    }
    return null;
  }

  // Utility: Send email verification
  private async sendEmailVerification(user: any, userId: string) {
    try {
      const mailUrl = this.configService.get("main_url");
      const token = await this.emailService.generateEmailVerificationToken(user.email, userId);
      const globalContext = {
        formattedDate: moment().format("dddd, MMMM D, YYYY"),
        id: userId,
        greeting: `Hello ${user.fname ? user.fname + " " + user.lname : "John Doe"}`,
        heading: "Welcome!",
        confirmEmail: true,
        para1: "Thank you for registering on our platform. You're almost ready to start.",
        para2: "Simply click the button below to confirm your email address and activate your account.",
        url: `${mailUrl}auth/verify-email?token=${token}`,
        title: "Confirm Your Email"
      };
      const mailSubject =
        "[Middn.io] Please verify your email address - https://ico.middn.com/";
      const mailSend = await this.emailService.sendVerificationEmail(user, globalContext, mailSubject);

      if (!mailSend) {
        return {
          status: HttpStatus.INTERNAL_SERVER_ERROR,
          body: { message: "Failed to send verification email" },
        };
      }
      return {
        status: HttpStatus.OK,
        body: { message: "User updated successfully. A verification email has been sent." },
      };
    } catch (error) {
      console.error("Error while sending email verification: ", error);
      return null;
    }
  }

  /**
   *  * This method retrieves user information based on the authenticated user's address.
   * @param req
   * @param response
   * @returns
   */
  @Get("/getuser")
  async getUser(@Req() req: any, @Res() response) {
    try {
      const { verifiedAddress } = req.headers.authData;

      // Fetch user details and full user data
      const userDetails = await this.userService.getFindbyAddress(verifiedAddress);
      const userId = userDetails._id.toString();
      const User = await this.userService.getUser(userId);

      // Initialize S3 and image variables
      const s3 = this.configService.get("s3");
      const bucketName = this.configService.get("aws_s3_bucket_name");
      let imageUrl = "";
      let newImage = "";

      // Generate signed URL for profile image if available
      if (User.profile) {
        newImage = await s3.getSignedUrl("getObject", {
          Bucket: bucketName,
          Key: User.profile
        });
        const options = {
          uri: newImage,
          encoding: null, // set encoding to null to receive the response body as a Buffer
        };
        const imageBuffer = await rp(options);
        imageUrl = "data:image/jpg;base64," + imageBuffer.toString("base64");
      }

      // Set default aliases if not provided
      if (!User.fname_alias) User.fname_alias = "John";
      if (!User.lname_alias) User.lname_alias = "Doe";

      // Extract sensitive fields and set headers dynamically
      const {
        is_2FA_login_verified,
        is_2FA_enabled,
        is_verified,
        kyc_completed,
        email_verified,
        email,
        phone,
        phoneCountry,
        is_2FA_twilio_login_verified,
        is_2FA_SMS_enabled,
        ...filteredUser
      } = User;

      const headers = {
        "2FA": User.is_2FA_login_verified,
        "2FA_enable": User.is_2FA_enabled,
        "2fa_sms_enable": User.is_2FA_SMS_enabled || false,
        "kyc_verify": User.is_verified,
        "kyc_status": User.kyc_completed,
        "is_email_verified": User.email_verified,
        "is_email": User.email ? this.emailService.encryptEmail(User.email) : null,
        "is_phone": User.phone ? this.emailService.encryptEmail(User.phone) : null,
        "is_phone_verified": User.phone_verified,
        "phone_code": User.phoneCountry ? this.emailService.encryptEmail(User.phoneCountry) : null,
        "2fa_twilio_verified": User.is_2FA_twilio_login_verified || false,  
      };
      
      // Set headers only for defined values
      Object.entries(headers).forEach(([key, value]) => value !== undefined && response.setHeader(key, value));
      // Remove sensitive fields before sending
      const { _doc } = filteredUser;
      const sensitiveFields = [
        "email", "phone", "is_2FA_twilio_login_verified", "is_2FA_SMS_enabled",
        "twilioOTP", "otpCreatedAt", "otpExpiresAt", "phoneCountry", "is_2FA_login_verified", 
        "is_2FA_enabled", "last_login", "email_verified", "phone_verified", "is_verified", "kyc_completed",
      ];
      
      const filteredDoc = Object.fromEntries(
        Object.entries(_doc).filter(([key]) => !sensitiveFields.includes(key))
      );
      
      return response.status(HttpStatus.OK).json({
        message: "User found successfully",
        User: filteredDoc,
        imageUrl,
      });
    } catch (err) {
      return response.status(HttpStatus.BAD_REQUEST).json({
        message: err.response?.message || "An error occurred",
        error: err.response || err.message,
      });
    }
  }

  /**
   *
   * @param req
   * @param response
   * @returns
   */
  @Get("/secret")
  async secret(@Req() req, @Res() response) {
    try {
      return response.status(HttpStatus.OK).json({ message: true });
    } catch (err) {
      return response.status(err.status).json(err.response);
    }
  }

  /**
   * This method handles user logout by deleting the authentication token associated with the user.
   * @param req
   * @param response
   * @param updateUsersDto
   * @returns
   */
  @Get("/logout")
  async logout(
    @Req() req: any,
    @Res() response,
    updateUsersDto: UpdateUserProfileDto
  ) {
    try {
      let userDetails = await this.userService.getFindbyAddress(
        req.headers.authData.verifiedAddress
      );
      const existingUser = await this.usersModel.findByIdAndUpdate(
        userDetails._id,
        { twilioOTP: null , otpCreatedAt : null,  otpExpiresAt : null},
        { new: true }
      )

      if (!existingUser) {
        throw new NotFoundException(`User #${userDetails._id} not found`);
      }
      
      const authHeader = req.headers["authorization"];
      const token = authHeader && authHeader.split(" ")[1];
      const isTokenDeleted = await this.tokenService.deleteToken(token);
      if (isTokenDeleted) {
        return response.status(HttpStatus.OK).json({
          message: "Logged out successfully",
        });
      } else {
        return response.status(HttpStatus.OK).json({
          message: "Something went wrong",
        });
      }
    } catch (err) {
      return response.status(err.status).json(err.response);
    }
  }

  /**
   * This method generates a secret key for enabling two-factor authentication (2FA) for the user.
   *
   * @param req
   * @param res
   * @returns
   */
  @SkipThrottle(false)
  @Get("/generate2FASecret")
  async generate2FASecret(@Req() req: any, @Res() res) {
    try {
      const user = await this.userService.getFindbyAddress(
        req.headers.authData.verifiedAddress
      );
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      if (user?.is_2FA_enabled === true) {
        return res
          .status(HttpStatus.BAD_REQUEST)
          .json({ message: "Authentication already enabled" });
      }
      const secret = speakeasy.generateSecret({ length: 20 });
      user.google_auth_secret = secret.base32;
      await user.save();
      res.json({
        secret: secret.base32,
      });
    } catch (err) {
      return res.status(err.status).json(err.response);
    }
  }

  /**
   * This method validates a Time-based One-Time Password (TOTP) token for two-factor authentication (2FA).
   * @param req
   * @param res
   * @returns
   */
  @SkipThrottle(false)
  @Post("validateTOTP")
  async validateTOTP(@Req() req: any, @Res() res) {
    try {
      const userAddress = req.headers.authData.verifiedAddress;
      const { token } = req.body;

      // Fetch user details
      const user = await this.userService.getFindbyAddress(userAddress);

      // Validate user and token
      if (!user) {
        return res.status(HttpStatus.NOT_FOUND).json({ message: "User not found" });
      }

      if (!token) {
        return res.status(HttpStatus.BAD_REQUEST).json({ message: "Code not provided" });
      }

      if (token.length !== 6) {
        return res.status(HttpStatus.BAD_REQUEST).json({ message: "Invalid code format" });
      }

      // Verify the TOTP token
      const verified = speakeasy.totp.verify({
        secret: user.google_auth_secret,
        encoding: "base32",
        token,
        window: 0,
      });

      if (verified) {
        user.is_2FA_enabled = true;
        user.is_2FA_login_verified = true;
        await user.save();
      }

      return res.status(HttpStatus.OK).json({ userId: user._id, verified });
    } catch (err) {
      return res.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
        message: err.message || "An error occurred while validating the code.",
      });
    }
  }

  /**
   *
   * @param req
   * @param res
   * @returns
   */
  @SkipThrottle(false)
  @Post("LoginFailedEmail")
  async LoginFailedEmail(@Req() req: any, @Res() res) {
    try {
      const userAddress = req.headers.authData.verifiedAddress;

      // Fetch user details
      const user = await this.userService.getFindbyAddress(userAddress);

      // Validate if email and email verification status are present
      if (user && user?.email && user?.email_verified) {
        const globalContext = {
          formattedDate: moment().format("dddd, MMMM D, YYYY"),
          greeting: `Hello ${
            user?.fname ? `${user.fname} ${user.lname}` : "John Doe"
          }`,
          title: "Unusual Login Email",
          para1: `Someone tried to log in too many times in your <a href="https://ico.middn.com/">https://ico.middn.com/</a> account.`,
        };
        const mailSubject = `[Middn.io] :: Unusual Login Attempt on https://ico.middn.com/ !!!!`;

        // Send email
        const isEmailSent = await this.emailService.sendVerificationEmail(
          user,
          globalContext,
          mailSubject
        );

        // Response based on email send status
        if (isEmailSent) {
          return res.status(HttpStatus.OK).json({
            message: "Email successfully sent.",
          });
        }

        return res.status(HttpStatus.BAD_REQUEST).json({
          message: "Failed to send email.",
        });
      }

      return res.status(HttpStatus.BAD_REQUEST).json({
        message: "User email not found or expired verification token",
      });
    } catch (error) {
      const errorMessage =
        error.name === "TokenExpiredError"
          ? "Expired Verification Token."
          : "Invalid Verification Token.";

      return res.status(HttpStatus.UNAUTHORIZED).json({
        message: errorMessage,
      });
    }
  }

  /**
   * This method disables two-factor authentication (2FA) for a user.
   * @param req
   * @param res
   * @returns
   */
  @SkipThrottle(false)
  @Get("disable2FA")
  async disable2FA(@Req() req: any, @Res() res) {
    try {
      const { verifiedAddress } = req.headers.authData;
      // Fetch the user by address
      const user = await this.userService.getFindbyAddress(verifiedAddress);

      if (!user) {
        return res
          .status(HttpStatus.NOT_FOUND)
          .json({ message: "User not found" });
      }

      if (!user.is_2FA_enabled) {
        return res
          .status(HttpStatus.BAD_REQUEST)
          .json({ message: "Authentication already disabled" });
      }

      // Disable 2FA
      user.is_2FA_enabled = false;
      user.is_2FA_login_verified = true;
      user.google_auth_secret = "";
      await user.save();

      // Send email notification if the user has verified email
      if (user.email && user.email_verified) {
        const globalContext = {
          formattedDate: moment().format("dddd, MMMM D, YYYY"),
          greeting: `Hello ${
            user?.fname ? user?.fname + " " + user?.lname + "," : "John Doe"
          }`,
          confirmEmail: false,
          para1:
            "We have reset your 2FA authentication as per your request via support.",
          para2:
            "If you want to reset 2FA authentication security on your account, click the button below to confirm and reset 2FA security.",
          title: "2FA Disable Confirmation by Admin",
        };

        const mailSubject = `[Middn.io] :: Disable 2FA Authentication Request`;
        const isVerified = await this.emailService.sendVerificationEmail(
          user,
          globalContext,
          mailSubject
        );

        if (!isVerified) {
          return res
            .status(HttpStatus.BAD_REQUEST)
            .json({ message: "Invalid or expired verification token." });
        }
      }

      // Success response
      return res
        .status(HttpStatus.OK)
        .json({ message: "2FA disabled successfully" });
    } catch (error) {
      const errorMessage =
        error.name === "TokenExpiredError"
          ? "Expired Verification Token."
          : "Invalid Verification Token";
      return res
        .status(HttpStatus.UNAUTHORIZED)
        .json({ message: errorMessage });
    }
  }

  /**
   *
   * @param response
   * @param req
   * @returns
   */
  @SkipThrottle(false)
  @Post("/changePassword")
  async changePassword(@Res() response, @Req() req: any) {
    try {
      const { oldPassword, newPassword, confirmPassword } = req.body;
      const userAddress = req.headers.authData.verifiedAddress;

      // Fetch user by address
      const user = await this.userService.getFindbyAddress(userAddress);

      // Validate user existence
      if (!user) {
        return response
          .status(HttpStatus.NOT_FOUND)
          .json({ message: "User not found." });
      }

      // Validate old password
      const isOldPasswordValid = await this.userService.comparePasswords(
        oldPassword,
        user.password
      );
      if (!isOldPasswordValid) {
        return response
          .status(HttpStatus.BAD_REQUEST)
          .json({ message: "Old password is incorrect." });
      }

      // Ensure new passwords match
      if (newPassword !== confirmPassword) {
        return response
          .status(HttpStatus.BAD_REQUEST)
          .json({ message: "New password and confirm password do not match." });
      }

      // Update password
      const hashedNewPassword = await this.userService.hashPassword(
        newPassword
      );
      const updateResult = await this.usersModel
        .updateOne({ email: user.email }, { password: hashedNewPassword })
        .exec();

      // Respond based on update result
      if (updateResult.modifiedCount > 0) {
        return response
          .status(HttpStatus.OK)
          .json({ message: "Your password has been changed successfully." });
      }

      return response.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
        message: "Failed to change password. Please try again later.",
      });
    } catch (error) {
      return response
        .status(HttpStatus.INTERNAL_SERVER_ERROR)
        .json({ message: error.message });
    }
  }
  
  @SkipThrottle(false)
  @Post("sendTOTP")
  async sendTOTP(@Req() req: any, @Res() res) {
    try {
      const user = await this.userService.getFindbyAddress(
        req.headers.authData.verifiedAddress
      );

      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }      
      const phoneNumber = req.body.phone;
      const phoneCountry = req.body.phoneCountry;

      if (!phoneNumber) {
        return res.status(400).json({ message: 'Phone number is required' });
      }

      if (!phoneCountry) {
        return res.status(400).json({ message: 'Phone code is required' });
      }

      if (this.emailService.decryptFun(phoneNumber) !== user.phone || this.emailService.decryptFun(phoneCountry) !== user.phoneCountry) {
        return res.status(400).json({ message: "Invalid mobile number or country code. Please check and try again."});
      }

      const otp = this.emailService.generateOTP(); // Generate the OTP
      const finalNumber = this.emailService.decryptFun(phoneCountry) + this.emailService.decryptFun(phoneNumber);

      try {
        const message = await this.emailService.sendOTP(finalNumber, otp); // Send OTP via SMS
        const currentDate = moment.utc().format();
        const otpExpiresAt = moment.utc().add(22, 'seconds').format(); // Set expiration 25 seconds from now
 
        // Update the user's OTP information
        await this.userService.updateOtp(
          user?._id,
          otp, 
          currentDate,
          otpExpiresAt
        );

        if (message?.sid) {
          return res.status(HttpStatus.OK).json({
            status: "success",
            message: 'OTP sent successfully',
            sid: message?.sid,
          });
        } else {
          return res.status(HttpStatus.BAD_REQUEST).json({ message: 'Failed to send OTP' });
        }
      } catch (error) {
        return res.status(HttpStatus.BAD_REQUEST).json({ message: 'Failed to send OTP', error });
      }
    } catch (err) {
      return res.status(HttpStatus.BAD_REQUEST).json(err.response);
    }
  }

  /**
   * 
   * @param req 
   * @param res 
   * @returns 
   */
  @SkipThrottle(false)
  @Post("verifyTOTP")
  async verifyTOTP(@Req() req: any, @Res() res) {
    try {
      const user = await this.userService.getFindbyAddress(
        req.headers.authData.verifiedAddress
      );

      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      const otp = req.body.token;
     
      if (!otp) {
        return res.status(400).json({ message: 'OTP is required' });
      }

      // Check if the OTP matches and is not expired
      const currentTime = moment.utc();
      const otpExpiresAt = moment.utc(user.otpExpiresAt);
      
      if (user?.twilioOTP !== otp) {
        return res.status(400).json({ message: 'Invalid OTP' });
      }

      if (currentTime.isAfter(otpExpiresAt)) {
        return res.status(400).json({ message: 'OTP has expired' });
      }

      // Mark the user's OTP as verified or perform any action (e.g., enabling 2FA)
      await this.userService.updateOtp(user._id, null, null, null); // Clear OTP fields

      // Optionally update other fields or handle verification logic
      const existingUser = await this.usersModel.findByIdAndUpdate(
        user._id,
        { is_2FA_twilio_login_verified : true },
        { new: true }
      )
      if (!existingUser) {
        throw new NotFoundException(`User #${user._id} not found`);
      }
      
      return res.status(HttpStatus.OK).json({
        status: "success",
        verified: true,
        message: 'OTP verified successfully',
      });

    } catch (err) {
      return res.status(HttpStatus.BAD_REQUEST).json({
        status: "error",
        message: "Failed to verify OTP",
        error: err.message,
      });
    }
  }

  /**
   * 
   * @param req 
   * @param res 
   * @returns 
  */
  @SkipThrottle(false)
  @Post("resendTOTP")
  async resendTOTP(@Req() req: any, @Res() res) {
    try {
      const user = await this.userService.getFindbyAddress(
        req.headers.authData.verifiedAddress
      );

      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }
      const phoneNumber = req.body.phone;
      const phoneCountry = req.body.phoneCountry;

      if (!phoneNumber) {
        return res.status(400).json({ message: 'Phone number is required' });
      }

      if (!phoneCountry) {
        return res.status(400).json({ message: 'Phone code is required' });
      }

      if (this.emailService.decryptFun(phoneNumber) !== user.phone || this.emailService.decryptFun(phoneCountry) !== user.phoneCountry) {
        return res.status(400).json({ message: "Invalid mobile number or country code. Please check and try again."});
      }

      const finalNumber = this.emailService.decryptFun(phoneCountry) + this.emailService.decryptFun(phoneNumber);
     
      // Check if an OTP already exists and is still valid
      const currentTime = moment.utc();
      if (user.otpExpiresAt && currentTime.isBefore(moment.utc(user.otpExpiresAt))) {
        return res.status(400).json({ 
          message: 'Existing OTP is still valid. Please wait for it to expire before requesting a new one.' 
        });
      }

      // Generate a new OTP and expiration time
      const otp = this.emailService.generateOTP();
      const currentDate = moment.utc().format();
      const otpExpiresAt = moment.utc().add(21, 'seconds').format(); // Set expiration 25 seconds from now

      try {
        const message = await this.emailService.sendOTP(finalNumber, otp); // Resend OTP via SMS
        
        // Update the user's OTP information
        await this.userService.updateOtp(
          user._id,
          otp,
          currentDate,
          otpExpiresAt
        );

        if (message?.sid) {
          return res.status(HttpStatus.OK).json({
            status: "success",
            message: 'OTP resend successfully',
            sid: message?.sid,
          });
        } else {
          return res.status(HttpStatus.BAD_REQUEST).json({ message: 'Failed to resend OTP' });
        }
      } catch (error) {
        return res.status(HttpStatus.BAD_REQUEST).json({ message: 'Failed to resend OTP', error });
      }
    } catch (err) {
      return res.status(HttpStatus.BAD_REQUEST).json({
        status: "error",
        message: "Failed to resend OTP",
        error: err.message,
      });
    }
  }
   /**
   * This method disables two-factor authentication (2FA) for a user.
   * @param req
   * @param res
   * @returns
   */
   @SkipThrottle(false)
   @Get("disable2FASMS")
   async disable2FASMS(@Req() req: any, @Res() res) {
     try {
       let user = await this.userService.getFindbyAddress(
         req.headers.authData.verifiedAddress
       );
       if (!user) {
         return res.status(404).json({ message: "User not found" });
       }
       user.is_2FA_SMS_enabled = !user.is_2FA_SMS_enabled;
       await user.save();   
       return res
          .status(HttpStatus.OK)
          .json({ message: `2FA ${user.is_2FA_SMS_enabled === null ? ("Disabled") : (user.is_2FA_SMS_enabled === false ? ("Disabled") : ("Enabled"))} successfully`});
     } catch (err) {
       return res.status(HttpStatus.BAD_REQUEST).json(err.response);
     }
   }
}
