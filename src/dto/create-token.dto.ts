import { IsOptional, IsString } from "class-validator";
export class CreateTokenDto {
	@IsOptional()
	@IsString()
	token: string;
}