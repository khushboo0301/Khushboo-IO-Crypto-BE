import { Document } from 'mongoose';
export interface ITransaction extends Document{
    readonly transactionHash: string;
    readonly status: string;
    readonly user_wallet_address: string;
    readonly receiver_wallet_address: string;
    readonly network: string;
    readonly price_currency: string;
    readonly is_sale: boolean;
    readonly is_process: boolean;
    readonly price_amount: string;
    readonly token_cryptoAmount : string;
    readonly gasUsed : string;
    readonly effectiveGasPrice : string;
    readonly cumulativeGasUsed : string;
    readonly blockNumber : string;
    readonly blockHash : string;
    readonly source : string;
    readonly created_at: string;
    readonly paid_at: string;
    readonly sale_name: string; 
    readonly sale_type: string;
}