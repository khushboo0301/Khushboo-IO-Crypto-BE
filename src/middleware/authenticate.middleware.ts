import {
  NestMiddleware,
  Injectable,
  HttpException,
  HttpStatus,
  Logger,
} from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { NextFunction, Request, Response } from "express";
import { Model } from "mongoose";
import { IUser } from "src/interface/users.interface";
import { TokenService } from "src/service/token/token.service";
const jwtSecret = "eplba";
let jwt = require("jsonwebtoken");

@Injectable()
export class AuthenticateMiddleware implements NestMiddleware {
  constructor(
    private readonly tokenService: TokenService,
    @InjectModel("user") private userModel: Model<IUser>
  ) {}

  async use(req: Request, res: Response, next: NextFunction) {
    try {

      res.header('Access-Control-Allow-Origin', '*'); // Allow all origins or specify your origin
      res.header(
        'Access-Control-Allow-Headers',
        'Origin, X-Requested-With, Content-Type, Accept, Authorization',
      );
      res.header(
        'Access-Control-Expose-Headers',
        'Content-Length, 2FA, 2FA_enable , kyc_verify, kyc_status, is_email_verified, is_email, is_phone, phone_code, 2fa_twilio_verified, 2fa_sms_enable',
      );
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
      // Extract the JWT token from the authorization header
      const authHeader = req.headers["authorization"];
      const token = authHeader && authHeader.split(" ")[1];

      // If no token provided, return UNAUTHORIZED status
      if (token == null) {
        throw new HttpException(
          "Authorization Token not found",
          HttpStatus.UNAUTHORIZED
        );
      }

      // Check if the token exists in the database
      const isExistingToken = await this.tokenService.getToken(token);

      // If token does not exist and the request is not a login attempt or a POST request, return UNAUTHORIZED status
      if (
        !isExistingToken &&
        req.method !== "POST" &&
        req.originalUrl !== "/login"
      ) {
        return res
          .status(HttpStatus.UNAUTHORIZED)
          .json({ message: "Authorization Token not valid." });
      }

      // Verify the JWT token
      jwt.verify(token, jwtSecret, async (err, authData) => {
        if (err) {
          return res
            .status(HttpStatus.UNAUTHORIZED)
            .json({ message: "Authorization Token not valid." });
        }
        
        // Extract verified user address from authData
        req.headers.address = authData.verifiedAddress;

        // Find user in the database based on wallet address
        const user = await this.userModel
          .findOne({ wallet_address: req.headers.address })
          .exec();

        // Handle cases where user is not found or account is suspended
        if (!user && !req.originalUrl.startsWith("/users/verify")) {
          let responseData: { message: string; logout?: any } = {
            message: "Account not found.",
          };
          if (req.originalUrl == "/users/logout") {
            responseData = { ...responseData, logout: true };
          }
          return res.status(HttpStatus.BAD_REQUEST).json(responseData);
        }
        if (user?.status === "Suspend") {
          let responseData: { message: string; logout?: any } = {
            message: "You are Suspended by Admin.",
          };
          if (req.originalUrl == "/users/logout") {
            responseData = { ...responseData, logout: true };
          }
          return res.status(HttpStatus.BAD_REQUEST).json(responseData);
        }
        
        // Attach authData to request headers for use in subsequent middleware or controllers
        req.headers.authData = authData;
        req.body.authData = authData;
        
        // Proceed to the next middleware or controller
        if (next) {
          next();
        }
      });
    } catch (error) {
      // Handle errors
      let errorMessage = "Internal server error";
      if (error.message === "Authorization Token not found") {
        errorMessage = error.message;
      }
      throw new HttpException(errorMessage, error);
    }
  }
}
