import { Document } from "mongoose";

export interface ISales extends Document {
  readonly name: string;
  readonly start_sale: string;
  readonly end_sale: string;
  readonly amount: number;
  readonly total_token: number;
  readonly remaining_token: number;
  readonly user_purchase_token: number;
}