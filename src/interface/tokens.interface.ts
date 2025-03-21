import { Document } from 'mongoose';
export interface IToken extends Document{
    readonly token: string;
}