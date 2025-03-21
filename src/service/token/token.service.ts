import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from "mongoose";
import { IToken } from 'src/interface/tokens.interface';
import { CreateTokenDto } from 'src/dto/create-token.dto';

@Injectable()
export class TokenService {
	constructor(
		@InjectModel('token') private tokenModel: Model<IToken>
	) { }

	async createToken(CreateTokenDtoValues: CreateTokenDto): Promise<IToken> {
		// Create a new token instance with the provided values
		const newToken = await new this.tokenModel(CreateTokenDtoValues);
		
		// Save the new token to the database
		return newToken.save();
	}

	async getToken(token: string): Promise<any> {
		// Find a token in the database that matches the provided token string
		const existingToken = await this.tokenModel.findOne({ token: token }).exec();
		
		// If no token is found, return false
		if (!existingToken) {
			return false;
		}
		// If a token is found, return true
		return true;
	}

	async deleteToken(token: string) {
		const deletedToken = await this.tokenModel.deleteOne({ token: token });
		if (!deletedToken) {
			return false;
		}
		return true;
	}	
}