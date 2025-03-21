import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";

@Schema()
export class User {
  @Prop()
  fname: string;
  @Prop()
  mname: string;
  @Prop()
  lname: string;
  @Prop()
  dob: string;
  @Prop()
  fullname: string;
  @Prop()
  phone: string;
  @Prop()
  phoneCountry: string;
  @Prop()
  cca3: string;
  @Prop()
  email: string;
  @Prop()
  currentpre: string;
  @Prop()
  city: string;
  @Prop()
  location: string;
  @Prop()
  wallet_address: string;
  @Prop()
  wallet_type: string;
  @Prop()
  nonce: string;
  @Prop()
  bio: string;
  @Prop()
  profile: string;
  @Prop()
  created_at: string;
  @Prop()
  updated_at: string;
  @Prop()
  nationality: string;
  @Prop()
  res_address: string;
  @Prop()
  postal_code: string;
  @Prop()
  country_of_issue: string;
  @Prop()
  verified_with: string;
  @Prop()
  passport_url: string;
  @Prop()
  user_photo_url: string;
  @Prop({ default: 0 })
  is_verified: number;
  @Prop({ default: false })
  kyc_completed: boolean;
  @Prop({ default: false })
  email_verified: boolean;
  @Prop()
  referred_by: string;
  @Prop({ default: "Active" })
  status: string;
  @Prop()
  last_login: string;
  @Prop({ default: false })
  is_kyc_deleted: boolean;
  @Prop()
  admin_checked_at: string;
  @Prop()
  kyc_submitted_date: string;
  @Prop()
  google_auth_secret: string;
  @Prop({ default: false })
  is_2FA_enabled: boolean;
  @Prop({ default: true })
  is_2FA_login_verified: boolean;
  @Prop()
	password: string;
  @Prop()
	twilioOTP: string;
  @Prop()
	otpCreatedAt: string;
	@Prop()
	otpExpiresAt: string;
  @Prop({ default: true })
	is_2FA_twilio_login_verified: boolean;
  @Prop({ default: false })
	is_2FA_SMS_enabled: boolean;
}
export const UserSchema = SchemaFactory.createForClass(User);
