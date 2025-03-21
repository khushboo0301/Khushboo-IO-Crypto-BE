import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose"
@Schema()
export class Token {
	@Prop()
	token: string;
}	
export const TokenSchema = SchemaFactory.createForClass(Token);