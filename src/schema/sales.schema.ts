import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose";

@Schema()
export class Sales {
	@Prop()
	name: string;
	@Prop()
	start_sale: string;
	@Prop()
	end_sale: string;
	@Prop()
	amount: number;
	@Prop()
	total_token: number;
	@Prop()
	remaining_token: number;
	@Prop()
	user_purchase_token: number;
}	
export const SalesSchema = SchemaFactory.createForClass(Sales);