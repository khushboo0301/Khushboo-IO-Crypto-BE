import { IsOptional, IsString } from "class-validator";
export class CreateUserDto {
	@IsOptional()
	@IsString()
	fname: string;
	
	@IsOptional()
	@IsString()
	lname: string;
	
	@IsOptional()
	@IsString()
	dob: string;

	@IsOptional()
	@IsString()
	fullname: string;

	@IsOptional()
	@IsString()
	phone: string;

	@IsOptional()
	@IsString()
	phoneCountry: string;

	@IsOptional()
	@IsString()
	cca3: string;

	@IsOptional()
	@IsString()
	currentpre: string;

	@IsOptional()
	@IsString()
	city: string;

	@IsOptional()
	@IsString()
	location: string;

	@IsOptional()
	@IsString()
	wallet_address: string;

	@IsOptional()
	@IsString()
	wallet_type: string;
	
	@IsOptional()
	@IsString()
	email: string;

	@IsOptional()
	@IsString()
	email_verified: boolean;

	@IsOptional()
	@IsString()
	nonce: string;

	@IsOptional()
    @IsString()
    createdAt: string;

	@IsOptional()
    @IsString()
    updatedAt: string;

	@IsOptional()
	@IsString()
	bio: string;

	@IsOptional()
	profile: Express.Multer.File;

	@IsOptional()
	@IsString()
	referred_by: string;

	@IsOptional()
	@IsString()
	last_login: string;

	@IsOptional()
	@IsString()
	created_at: string;

	@IsOptional()
	@IsString()
	is_2FA_login_verified: string;

	@IsOptional()
	@IsString()
	password: string;

    @IsOptional()
	@IsString()
	twilioOTP: string;

	@IsOptional()
	@IsString()
	otpCreatedAt: string;

	@IsOptional()
	@IsString()
	otpExpiresAt: string;

	@IsOptional()
	@IsString()
	is_2FA_twilio_login_verified: boolean; 

	@IsOptional()
	@IsString()
	is_2FA_SMS_enabled: boolean;
  
}
