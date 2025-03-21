import { IsArray, IsOptional, IsString } from "class-validator";
export class CreateTransactionDto {

	@IsOptional()
	transactionHash: string;

	@IsOptional()
	@IsString()
	status: string;

	@IsOptional()
	@IsString()
	user_wallet_address: string;
	
	@IsOptional()
	@IsString()
	receiver_wallet_address: string;

	@IsOptional()
	@IsString()
	network: string;

	@IsOptional()
	@IsString()
	price_currency: string;

	@IsOptional()
	@IsString()
	is_sale: boolean;

	@IsOptional()
	@IsString()
	is_process: boolean;

	@IsOptional()
	@IsString()
	price_amount: string;

	@IsOptional()
	@IsString()
	token_cryptoAmount: string;
	
	@IsOptional()
	@IsString()
	gasUsed: string;

	@IsOptional()
	@IsString()
	effectiveGasPrice: string;

	@IsOptional()
	@IsString()
	cumulativeGasUsed: string;

	@IsOptional()
	@IsString()
	blockNumber: string;

	@IsOptional()
	@IsString()
	blockHash: string;

	@IsOptional()
	@IsString()
	source: string;

	@IsOptional()
	@IsString()
	created_at: string;

	@IsOptional()
	@IsString()
	paid_at: string;

	@IsOptional()
	@IsString()
	sale_name: string;

	@IsOptional()
	@IsString()
	sale_type: string;
}