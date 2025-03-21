import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose"
@Schema()
export class Transaction {
	@Prop()
	transactionHash: string;

	@Prop()
	status: string;

	@Prop()
	user_wallet_address: string;

	@Prop()
	receiver_wallet_address: string;

	@Prop()
	network: string;
	
	@Prop()
	price_currency: string;

	@Prop()
	is_sale: boolean;

	@Prop()
	is_process: boolean;

	@Prop()
	price_amount: string;

	@Prop()
	token_cryptoAmount: string;

	@Prop()
	gasUsed: string;

	@Prop()
	effectiveGasPrice: string;

	@Prop()
	cumulativeGasUsed: string;
	
	@Prop()
	blockNumber: string;

	@Prop()
	blockHash: string;

	@Prop()
	created_at: string;
	
	@Prop()
	paid_at: string;

	@Prop()
	source: string;

	@Prop()
	sale_name: string;

	@Prop()
	sale_type: string;
}	
export const TransactionSchema = SchemaFactory.createForClass(Transaction);