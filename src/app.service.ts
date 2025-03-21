import { Inject, Injectable } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { Model } from "mongoose";
import { TransactionsService } from "src/service/transaction/transactions.service";
import moment from "moment";
import * as schedule from "node-schedule";
import Web3 from "web3";
import axios from "axios";
import { Cron } from "@nestjs/schedule";
import { ISales } from "src/interface/sales.interface";
import { IUser } from "src/interface/users.interface";
import { ConfigService } from "@nestjs/config";
import { database, firebaseMessages } from "./config/firebaseConfig";
import { get,  ref, set, update } from "firebase/database";
import { MailerService } from "@nestjs-modules/mailer";
import { EmailService } from "src/service/email/email.service";
import { CACHE_MANAGER } from '@nestjs/cache-manager';
import { Cache } from 'cache-manager';

const ETHERSCAN_API_KEY = "7ATF9VTNMJCSVFCYYKA5HJBAFI5FEX8TCF";
const BSCSCAN_API_KEY = "W11WIQSRZBP3CV14T5K94BD113HX1ASP77";
const FANTOM_API_KEY = "AMEB7ZHTNCBV5WAVB9UC7WBIZV9Z9ZQSCN";
const POLYGON_API_KEY = "11KMKMT41HFN8HXVJDWXUW2MFSJJFXY34H";
const ETH_CONTRACT_ADDRESS = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
const FTM_USDT_ADDRESS = "0x049d68029688eAbF473097a2fC38ef61633A3C7A";
const MATIC_USDT_ADDRESS = "0xc2132d05d31c914a87c6611c10748aeb04b58e8f";
const BNB_USDT_ADDRESS = "0x55d398326f99059fF775485246999027B3197955";

@Injectable()
export class AppService {
  private web3: Web3;
  private scheduledTime: moment.Moment;
  private scheduledTimeMain: moment.Moment;
  
  constructor(
    @InjectModel("user") private userModel: Model<IUser>,
    @InjectModel("transaction") private transactionModel: Model<any>,
    @InjectModel("sales") private salesModel: Model<ISales>,
    @Inject(CACHE_MANAGER) private cacheManager: Cache,
    private readonly transactionService: TransactionsService,
    private readonly configService: ConfigService,
    private readonly mailerService: MailerService,
    private readonly emailService: EmailService,
  ) {
    this.web3 = new Web3(
      new Web3.providers.HttpProvider(
        "https://mainnet.infura.io/v3/b16f8eb83d5749d18959c29c249e51f1"
      )
    );
    this.scheduleRecurringCheck();
  }
  
  async clearCache() {
    await this.cacheManager.reset(); // Clears the entire cache
  }

  async clearSpecificKey(key: string) {
    await this.cacheManager.del(key); // Clears a specific key from the cache
  }

  getHello(): string {
    return 'Hello World!';
  }

  private async fetchTransactionData() {
    const networks = {
      FTM: {
        usdtAddress: FTM_USDT_ADDRESS,
        apiKey: FANTOM_API_KEY,
        network: "FTM",
      },
      ETH: {
        usdtAddress: ETH_CONTRACT_ADDRESS,
        apiKey: ETHERSCAN_API_KEY,
        network: "ETH",
      },
      BNB: {
        usdtAddress: BNB_USDT_ADDRESS,
        apiKey: BSCSCAN_API_KEY,
        network: "BNB",
      },
      MATIC: {
        usdtAddress: MATIC_USDT_ADDRESS,
        apiKey: POLYGON_API_KEY,
        network: "MATIC",
      },
    };

    // Calculate block numbers for the last 2 hours
    try {
      const responsesPending = await Promise.all([
        this.fetchPendingTransactionsForNetwork(networks["FTM"]),
        this.fetchPendingTransactionsForNetwork(networks["ETH"]),
        this.fetchPendingTransactionsForNetwork(networks["BNB"]),
        this.fetchPendingTransactionsForNetwork(networks["MATIC"])
      ]);

      let allTransactionsPending = [];
      for (let i = 0; i < responsesPending.length; i++) {
        const transactions = await this.parsePendingLogs(
          responsesPending[i],
          Object.keys(networks)[i]
        )
        allTransactionsPending = allTransactionsPending.concat(transactions);
      }

      const userPendingTransactions = await Promise.all(
        allTransactionsPending.map(async (tx) => {
          const data = await this.transactionService.getTransactionByOredrId(
            tx.transactionHash
          );
          if (!data) return tx;
          return null;
        })
      );

      const pentransactionsWithNoData = userPendingTransactions.filter(
        (tx) => tx !== null
      );
      await Promise.all(
        pentransactionsWithNoData.map(async (tx) => {
          const usdtAmount = parseFloat(
            this.web3.utils.fromWei(tx.value, "ether")
          );
          const formattedCurrentDate = moment(tx.createDate).format(
            "YYYY-MM-DD[T]HH:mm:ss[Z]"
          );
          let sales = await this.transactionService.checkOutsideSales(
            formattedCurrentDate
          );

          let cryptoAmount = 0;
          let is_sale = false;
          if (sales) {
            cryptoAmount = usdtAmount / sales.amount;
            is_sale = true;
          } else {
            sales = await this.transactionService.checkOutsideNearSales(
              formattedCurrentDate
            );
            if (sales) {
              cryptoAmount = usdtAmount / sales.amount;
              is_sale = false;
            } else {
              is_sale = false;
              cryptoAmount = 0;
            }
          }
          const createOrder = {
            transactionHash: tx.transactionHash,
            price_amount:usdtAmount,
            status: "pending",
            user_wallet_address: tx.from,
            receiver_wallet_address: tx.to,
            blockHash: tx.blockHash,
            effectiveGasPrice: tx.gasPrice,
            gasUsed: tx.gasUsed,
            price_currency: "USDT",
            created_at: moment.utc().format(),
            paid_at: tx.createDate,
            blockNumber: tx.blockNumber,
            source: "purchase",
            network: tx.network,
            amount: usdtAmount,
            token_cryptoAmount: cryptoAmount.toFixed(2),
            is_sale: is_sale,
            is_process: false,
            sale_name: sales.name,
            sale_type: "outside-website"
          };
          await this.transactionService.createTransaction(
            createOrder
          )
          const userRef = ref(
            database,
            firebaseMessages.ICO_TRANSACTIONS + "/" + tx.transactionHash
          )
          get(userRef)
          .then(async (snapshot) => {
            set(userRef, {
              lastActive: Date.now(),
              is_open: false,
              is_sale: is_sale,
              is_process: false,
              user_wallet_address: tx.from,
              status: "pending",
              is_pending: false
            });
          })
          .catch((error) => {
            console.error("Error adding/updating user in Firebase:", error);
          });
        })
      );
    } catch (error) {
      console.error("Error fetching transaction data:", error);
    }
  }

  private async fetchTransactionFailedData() {
    const networks = {
      FTM: {
        usdtAddress: FTM_USDT_ADDRESS,
        apiKey: FANTOM_API_KEY,
        network: "FTM",
      },
      ETH: {
        usdtAddress: ETH_CONTRACT_ADDRESS,
        apiKey: ETHERSCAN_API_KEY,
        network: "ETH",
      },
      BNB: {
        usdtAddress: BNB_USDT_ADDRESS,
        apiKey: BSCSCAN_API_KEY,
        network: "BNB",
      },
      MATIC: {
        usdtAddress: MATIC_USDT_ADDRESS,
        apiKey: POLYGON_API_KEY,
        network: "MATIC",
      },
    };

    // Calculate block numbers for the last 2 hours
    try {
      const responsesPending = await Promise.all([
        this.fetchFailedTransactionsForNetwork(networks["FTM"]),
        this.fetchFailedTransactionsForNetwork(networks["ETH"]),
        this.fetchFailedTransactionsForNetwork(networks["BNB"]),
        this.fetchFailedTransactionsForNetwork(networks["MATIC"])
      ]);

      let allTransactionsFailed = [];
      for (let i = 0; i < responsesPending.length; i++) {
        const transactions = await this.parsePendingLogs(
          responsesPending[i],
          Object.keys(networks)[i]
        );
        allTransactionsFailed = allTransactionsFailed.concat(transactions);
      }

      const userFailedTransactions = await Promise.all(
        allTransactionsFailed.map(async (tx) => {
          const data = await this.transactionService.getTransactionByOredrId(
            tx.transactionHash
          );
          if (!data) return tx;
          return null;
        })
      );

      const failtransactionsWithNoData = userFailedTransactions.filter(
        (tx) => tx !== null
      );
      await Promise.all(
        failtransactionsWithNoData.map(async (tx) => {
          const usdtAmount = parseFloat(
            this.web3.utils.fromWei(tx.value, "ether")
          );
          const formattedCurrentDate = moment(tx.createDate).format(
            "YYYY-MM-DD[T]HH:mm:ss[Z]"
          );
          let sales = await this.transactionService.checkOutsideSales(
            formattedCurrentDate
          );

          let cryptoAmount = 0;
          let is_sale = false;
          if (sales) {
            cryptoAmount = usdtAmount / sales.amount;
            is_sale = true;
          } else {
            sales = await this.transactionService.checkOutsideNearSales(
              formattedCurrentDate
            );
            if (sales) {
              cryptoAmount = usdtAmount / sales.amount;
              is_sale = false;
            } else {
              is_sale = false;
              cryptoAmount = 0;
            }
          }
          const createOrder = {
            transactionHash: tx.transactionHash,
            price_amount:usdtAmount,
            status: "failed",
            user_wallet_address: tx.from,
            receiver_wallet_address: tx.to,
            blockHash: tx.blockHash,
            effectiveGasPrice: tx.gasPrice,
            gasUsed: tx.gasUsed,
            price_currency: "USDT",
            created_at: moment.utc().format(),
            paid_at: tx.createDate,
            blockNumber: tx.blockNumber,
            source: "purchase",
            network: tx.network,
            amount: usdtAmount,
            token_cryptoAmount: cryptoAmount.toFixed(2),
            is_sale: is_sale,
            is_process: false,
            sale_name: sales.name,
            sale_type: "outside-website"
          };
          await this.transactionService.createTransaction(
            createOrder
          )
          const userRef = ref(
            database,
            firebaseMessages.ICO_TRANSACTIONS + "/" + tx.transactionHash
          )
          get(userRef)
          .then(async (snapshot) => {
            set(userRef, {
              lastActive: Date.now(),
              is_open: false,
              is_sale: is_sale,
              is_process: false,
              user_wallet_address: tx.from,
              status: "failed",
              is_pending: false
            });
          })
          .catch((error) => {
            console.error("Error adding/updating user in Firebase:", error);
          });
        })
      );
    } catch (error) {
      console.error("Error fetching transaction data:", error);
    }
  }

  private async fetchTransactionPaidData() {
    const networks = {
      FTM: {
        usdtAddress: FTM_USDT_ADDRESS,
        apiKey: FANTOM_API_KEY,
        network: "FTM",
      },
      ETH: {
        usdtAddress: ETH_CONTRACT_ADDRESS,
        apiKey: ETHERSCAN_API_KEY,
        network: "ETH",
      },
      BNB: {
        usdtAddress: BNB_USDT_ADDRESS,
        apiKey: BSCSCAN_API_KEY,
        network: "BNB",
      },
      MATIC: {
        usdtAddress: MATIC_USDT_ADDRESS,
        apiKey: POLYGON_API_KEY,
        network: "MATIC",
      },
    };

    // Calculate block numbers for the last 2 hours
    try {
      const responses = await Promise.all([
        this.fetchTransactionsForNetwork(networks["FTM"]),
        this.fetchTransactionsForNetwork(networks["ETH"]),
        this.fetchTransactionsForNetwork(networks["BNB"]),
        this.fetchTransactionsForNetwork(
          networks["MATIC"])
      ]);

      let allTransactions = [];
      for (let i = 0; i < responses.length; i++) {
        const transactions = await this.parseLogs(
          responses[i],
          Object.keys(networks)[i]
        );
        allTransactions = allTransactions?.concat(transactions);
      }

      const userTransactions = [];

      for (const tx of allTransactions) {
        try {
          const data = await this.transactionService.getTransactionByOredrId(tx.transactionHash);
          if (!data) {
            userTransactions.push(tx);
            continue;
          }
      
          if (data.status === "pending") {
            const updateData = { status: "paid" };
            await this.transactionService.updateTransactionData(data.transactionHash, updateData);
           
            const existingUser = await this.userModel
            .findOne({wallet_address: data.user_wallet_address})
            .select("id wallet_address fname lname email email_verified is_verified kyc_completed")

            const usdtAmount = parseFloat(
              this.web3.utils.fromWei(tx.value, "ether")
            )
            if(existingUser && existingUser?.email && existingUser?.email_verified){
              const globalContext = {
                formattedDate: moment().format('dddd, MMMM D, YYYY'),
                heading: "Thank you for your contribution!",
                para1: `You have requested to purchase ${tx.network} token. Your order has been received and is now being waiting for payment. You order details are show below for your reference.`,
                para2: `Your token balance will appear in your account as soon as we have confirmed your payment from ${existingUser?.wallet_address}`,
                para3: "Feel free to contact us if you have any questions.",
                order_details: "Order Details:",
                order_id: `OrderID: ${data?._id}`,
                transactionHash: `TransactionHash: ${data?.transactionHash}`,
                price_amount: `Amount: ${usdtAmount}`,
                title: "Token Purchase - Order Placed by Manual payment"
              }
  
              const mailSubject = `[Middn.io] Order placed for Token Purchase #${existingUser?._id}`;
              await this.emailService.sendVerificationEmail(
                existingUser,
                globalContext,
                mailSubject
              );
            }
           
            const userRef = ref(
              database,
              firebaseMessages.ICO_TRANSACTIONS + "/" + data.transactionHash
            )
            get(userRef)
            .then(async (snapshot) => {
              if (snapshot.exists()) {
                update(userRef, {
                  lastActive: Date.now(),
                  is_pending: true,
                  status: "paid"
                });
              }
            })
            .catch((error) => {
              console.error("Error adding/updating user in Firebase:", error);
            });

            if (existingUser && existingUser.kyc_completed === false) {
              return null;
            }
            if (
              existingUser && existingUser?.is_verified === 1 &&
              existingUser?.kyc_completed === true 
            ) {
              
              if (data && data.is_sale) {
                const latestSales = await this.transactionService.getSalesByName(data.sale_name);
                const userPurchaseMid = Number(latestSales?.user_purchase_token) + parseFloat(data.token_cryptoAmount)
                const remainingMid= Number(latestSales?.remaining_token) - parseFloat(data.token_cryptoAmount);
                
                if (remainingMid <= 0 || remainingMid - parseFloat(data.token_cryptoAmount) < 0) {
                  return null;
                }
                const updatedSaleValues = {
                  user_purchase_token: parseFloat(userPurchaseMid.toFixed(2)),
                  remaining_token: parseFloat(remainingMid.toFixed(2))
                } 
                await this.salesModel.updateOne({ _id: latestSales?._id }, { $set: updatedSaleValues });
                await this.transactionService.updateTransactionData(data.transactionHash, {is_process: true});
               
                get(userRef)
                .then(async (snapshot) => {
                  if (snapshot.exists()) {
                    update(userRef, {
                      lastActive: Date.now(),
                      is_process: true,
                    });
                  }
                })
              }
            }
          } else if (data.status === "paid") {
            continue;
          }
          userTransactions.push(null);
        } catch (error) {
          userTransactions.push(null);
        }
      }
      const transactionsWithNoData = userTransactions.filter((tx) => tx !== null);
     
      await Promise.all(
        transactionsWithNoData.map(async (tx) => {
          const usdtAmount = parseFloat(
            this.web3.utils.fromWei(tx.value, "ether")
          );
          const formattedCurrentDate = moment(tx.createDate).format(
            "YYYY-MM-DD[T]HH:mm:ss[Z]"
          );
          let sales = await this.transactionService.checkOutsideSales(
            formattedCurrentDate
          );
          
          let cryptoAmount = 0;
          let is_sale = false;
          let userPurchaseMid;
          let remainingMid;
          if (sales) {
            cryptoAmount = usdtAmount / sales.amount;
            is_sale = true;
            userPurchaseMid = parseFloat(cryptoAmount.toFixed(2)) + sales.user_purchase_token;
            remainingMid = sales.remaining_token - parseFloat(cryptoAmount.toFixed(2));

            if (remainingMid <= 0 || remainingMid - parseFloat(cryptoAmount.toFixed(2)) < 0) {
              return null;
            }
          } else {
            sales = await this.transactionService.checkOutsideNearSales(
              formattedCurrentDate
            );
            if (sales) {
              cryptoAmount = usdtAmount / sales.amount;
              is_sale = false;
            } else {
              is_sale = false;
              cryptoAmount = 0;
            }
          }
          const createOrder = {
            transactionHash: tx.transactionHash,
            price_amount:usdtAmount,
            status: tx.method === "transfer" ? "paid" : "pending",
            user_wallet_address: tx.from,
            receiver_wallet_address: tx.to,
            blockHash: tx.blockHash,
            effectiveGasPrice: tx.gasPrice,
            gasUsed: tx.gasUsed,
            price_currency: "USDT",
            created_at: moment.utc().format(),
            paid_at: tx.createDate,
            blockNumber: tx.blockNumber,
            source: "purchase",
            network: tx.network,
            amount: this.web3.utils.fromWei(tx.value, "ether"),
            token_cryptoAmount: cryptoAmount.toFixed(2),
            is_sale: is_sale,
            is_process: false,
            sale_name: sales && sales.name ? sales.name : null,
            sale_type: "outside-website"
          };
          const transaction = await this.transactionService.createTransaction(
            createOrder
          );
          const userRef = ref(
            database,
            firebaseMessages.ICO_TRANSACTIONS + "/" + tx.transactionHash
          )
          get(userRef)
          .then(async (snapshot) => {
              set(userRef, {
                lastActive: Date.now(),
                is_open: false,
                is_sale: is_sale,
                is_process: false,
                user_wallet_address: tx.from,
                status: "paid",
                is_pending: true
              });
          })
          .catch((error) => {
            console.error("Error adding/updating user in Firebase:", error);
          });

          if(transaction)
          {
            const existingUser = await this.userModel
            .findOne({wallet_address: transaction.user_wallet_address})
            .select("id wallet_address is_verified kyc_completed")

            if (existingUser && existingUser.kyc_completed === false) {
              return null; // Skip this transaction
            }
            if (
              existingUser && existingUser?.is_verified === 1 &&
              existingUser?.kyc_completed === true 
            ) {
              if (transaction.is_sale) {
                const updatedSalevalues = {
                  $set: {
                    user_purchase_token: parseFloat(userPurchaseMid.toFixed(2)),
                    remaining_token: parseFloat(remainingMid.toFixed(2)),
                  },
                };
                await this.salesModel.updateOne(
                  { _id: sales?._id },
                  updatedSalevalues
                );
                await this.transactionService.updateTransactionData(tx.transactionHash, {is_process: true});
                get(userRef)
                .then(async (snapshot) => {
                  if (snapshot.exists()) {
                    update(userRef, {
                      lastActive: Date.now(),
                      is_process: true,
                    });
                  }
                })
                .catch((error) => {
                  console.error("Error adding/updating user in Firebase:", error);
                });
              }
            }
          }
          return 
        })
      );
    } catch (error) {
      console.error("Error fetching transaction data:", error);
    }
  }

  private async fetchTransactionsForNetwork(
    networkData: any
  ) {
    const { usdtAddress, apiKey } = networkData;
    const baseUrl = this.getBaseUrlForNetwork(networkData);
    try {
      const receiver_address = this.configService.get('receiver_address')
      const response = await axios.get(baseUrl, {
        params: {
          module: "logs",
          action: "getLogs",
          address: usdtAddress,
          fromBlock: "0",
          toBlock: "latest",
          topic0:
            "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef", // Transfer event signature
          topic2: `0x${receiver_address.slice(2)
            .toLowerCase()
            .padStart(64, "0")}`,
          apikey: apiKey,
        }
      });
      return response.data.result;
    } catch (error) {
      console.error("Error fetching pending transactions:", error);
      return [];
    }
  }

  private async parseLogs(logs: any[], network: string) {
    try {
      let parsedTransactions = [];
      const receiver_address = this.configService.get('receiver_address')
      for (const log of logs) {
        try {
          const to = `0x${log.topics[2].slice(26)}`;
          if (log && to && to.toLowerCase() === receiver_address.toLowerCase()){
          const gasPrice = log.gasPrice ? this.web3.utils.hexToNumberString(log.gasPrice) : '0';
          const gasUsed = log.gasUsed ? this.web3.utils.hexToNumberString(log.gasUsed) : '0';
          
          // Fetch date and method details
          const { date, method } = await this.getBlockDateAndTransactionDetails(
            log.blockNumber,
            log.transactionHash,
            network
          );
          // Check if transaction date is within the last 10 minutes
          if (!this.isWithinLast10Minutes(date)) {
            continue;
          }
  
          // Check for transfer method and valid topics
          if (
            method === "transfer" &&
            log.topics &&
            log.topics.length >= 3 &&
            typeof log.topics[1] === "string" &&
            typeof log.topics[2] === "string"
          ) {
            const from = `0x${log.topics[1].slice(26)}`;
            const value = this.web3.utils.hexToNumberString(log.data);
            const transaction = {
              from,
              to,
              value,
              blockHash: log.blockHash,
              gasPrice,
              gasUsed,
              transactionHash: log.transactionHash,
              blockNumber: log.blockNumber,
              createDate: date,
              method,
              network,
            };
            parsedTransactions.push(transaction);
          }
          }
        } catch (error) {
          console.error(`Error parsing log for transaction ${log.transactionHash}:`, error);
        }
      }
      return parsedTransactions;
    } catch (error) {
      console.error("Error in parseLogs:", error);
      return [];
    }
  }

  private async getBlockDateAndTransactionDetails(
    blockNumber: number,
    transactionHash: string,
    network: string
  ) {
    const apiKey = this.getApiKeyForNetwork(network);
    const baseUrl = this.getBaseUrlForNetwork({ network });
  
    try {
      const [blockResponse, transactionResponse] = await Promise.all([
        axios.get(baseUrl, {
          params: {
            module: "proxy",
            action: "eth_getBlockByNumber",
            tag: this.web3.utils.toHex(blockNumber),
            boolean: true,
            apikey: apiKey,
          },
        }),
        axios.get(baseUrl, {
          params: {
            module: "proxy",
            action: "eth_getTransactionByHash",
            txhash: transactionHash,
            apikey: apiKey,
          },
        }),
      ]);
      const hexTimestamp = blockResponse.data.result.timestamp;
      const timestamp = parseInt(hexTimestamp, 16);
      
      // Verify the timestamp is in seconds
      if (!timestamp || isNaN(timestamp) || timestamp.toString().length > 10) {
        throw new Error("Invalid timestamp value");
      }
      const input = transactionResponse.data.result?.input;
      
      if (!input) {
        throw new Error("Transaction input is undefined");
      }
  
      const method = this.decodeMethod(input);
      const formattedDate = moment.unix(timestamp).utc().format();
      return {
        date: formattedDate,
        method: method,
      };
    } catch (error) {
      console.error("Error in getBlockDateAndTransactionDetails:", error);
      throw error;
    }
  }
  
  private async fetchPendingTransactionsForNetwork(networkData: any) {
    const { usdtAddress, apiKey } = networkData;
    const baseUrl = this.getBaseUrlForNetwork(networkData);
    try {
      const receiver_address = this.configService.get('receiver_address')
      const response = await axios.get(baseUrl, {
        params: {
          module: 'account',
          action: 'tokentx',
          contractaddress: usdtAddress,
          sort: 'pending',
          apikey: apiKey,
          address: receiver_address,
        }
      });
      return response.data.result;
    } catch (error) {
      console.error("Error fetching pending transactions:", error);
      return [];
    }
  }

  private async fetchFailedTransactionsForNetwork(networkData: any) {
    const { usdtAddress, apiKey } = networkData;
    const baseUrl = this.getBaseUrlForNetwork(networkData);
    const receiver_address = this.configService.get('receiver_address')
      
    try {
      // Fetch all token transactions
      const response = await axios.get(baseUrl, {
        params: {
          module: 'account',
          action: 'tokentx',
          contractaddress: usdtAddress,
          sort: 'desc', // Use 'desc' to get the most recent transactions first
          apikey: apiKey,
          address: receiver_address,
        }
      });
  
      // Filter for failed transactions
      const allTransactions = response.data.result;
      const failedTransactions = allTransactions?.filter(tx => tx.isError === '1');
      return failedTransactions;
    } catch (error) {
      console.error("Error fetching failed transactions:", error);
      return [];
    }
  }
  
  private async parsePendingLogs(logs: any[], network: string) {
    try {
      let parsedTransactions = [];
      const receiver_address = this.configService.get('receiver_address')
    
      for (const log of logs) {
        try {
          const formattedDate = moment.unix(log.timeStamp).utc().format();

          if (log && log.to && log.to.toLowerCase() === receiver_address.toLowerCase()){
            if (!this.isWithinLast10Minutes(formattedDate)) {
              continue;
            }    
            const transaction = {
              from: log.from,
              to: log.to,
              value: log.value,
              blockHash: log.blockHash,
              gasPrice: log.gasPrice,
              gasUsed: log.gasUsed,
              transactionHash: log.hash,
              blockNumber: log.blockNumber,
              createDate: formattedDate,
              network,
            };
            parsedTransactions.push(transaction);
          }
        } catch (error) {
          console.error(`Error parsing log for transaction ${log.hash}:`, error);
        }
      }
      return parsedTransactions;
    } catch (error) {
      console.error("Error in parseLogs:", error);
      return [];
    }
  }
  
  private getApiKeyForNetwork(network: string) {
    const apiKeys = {
      FTM: FANTOM_API_KEY,
      ETH: ETHERSCAN_API_KEY,
      BNB: BSCSCAN_API_KEY,
      MATIC: POLYGON_API_KEY,
    };

    return apiKeys[network];
  }

  private getBaseUrlForNetwork(networkData: any) {
    switch (networkData.network) {
      case "ETH":
        return "https://api.etherscan.io/api";
      case "BNB":
        return "https://api.bscscan.com/api";
      case "FTM":
        return "https://api.ftmscan.com/api";
      case "MATIC":
        return "https://api.polygonscan.com/api";
      default:
        throw new Error(`Unsupported network: ${networkData.network}`);
    }
  }

  private decodeMethod(input: string) {
    if (!input || typeof input !== 'string') {
      throw new Error("Invalid input for decodeMethod");
    }
  
    const methodSignature = input.slice(0, 10); // First 4 bytes of the input
    const methods = {
      "0xa9059cbb": "transfer", // ERC20 Transfer
      "0x095ea7b3": "approve", // ERC20 Approve
      "0x23b872dd": "transferFrom",
    };
    return methods[methodSignature] || "unknown";
  }

  private isWithinLast10Minutes(date: string): boolean {
    const currentTime = moment.utc();
    const transactionTime = moment.utc(date);
    const twoHoursAgo = currentTime.clone().subtract(1, "days");
    return transactionTime.isBetween(twoHoursAgo, currentTime);
  }

  //Cron run every 30 sec to get outside website transactions 
  @Cron("*/30 * * * * *")
  async handleCron() {
    try {
      const currentTime = moment.utc().format();
      console.log(`cron is running ${currentTime}`)
      await this.fetchTransactionData();
      await this.fetchTransactionFailedData();
    } catch (error) {
      console.error(error);
    }
  }

  @Cron("*/1 * * * *")
  async handleCrons() {
    try {
      const currentTime = moment.utc().format();
      console.log(`cron is running ${currentTime}`)
      await this.fetchTransactionPaidData();
    } catch (error) {
      console.error(error);
    }
  }

  async scheduleTargetTimeCron() {
    try {
      const currentTime = moment.utc();
      const sales = await this.transactionService.getAllSales();
      const preSaleDate = sales[0].start_sale;
      const mainSaleDate = sales[1].start_sale;

      this.scheduledTime = moment.utc(preSaleDate);
      this.scheduledTimeMain = moment.utc(mainSaleDate);

      const tolerance = 1000; // 1 second in milliseconds

      if (Math.abs(currentTime.diff(this.scheduledTime, 'milliseconds')) <= tolerance) {
        const transactions = await this.transactionModel
          .find({ sale_name: "pre-sale", is_sale: false, status :"paid" })
          .exec();

        await Promise.all(transactions.map(async transaction => {
          if (transaction.transactionHash) {
            const currentSales = await this.transactionService.getAllSales();
            let userPurchaseMid = parseFloat(transaction.token_cryptoAmount.toFixed(2)) + currentSales[0].user_purchase_token;
            let remainingMid = currentSales[0].total_token - userPurchaseMid;
            if (remainingMid <= 0 || remainingMid - parseFloat(transaction.token_cryptoAmount.toFixed(2)) < 0) {
              return null;
            }
            
            const existingUser = await this.userModel
            .findOne({wallet_address: transaction.user_wallet_address})
            .select("id wallet_address is_verified kyc_completed")

            if (existingUser && existingUser.kyc_completed === false) {
              return null; // Skip this transaction
            }
            if (
              existingUser && existingUser?.is_verified === 1 &&
              existingUser?.kyc_completed === true 
            ){
              const updatedSaleValues = {
                $set: {
                  user_purchase_token: parseFloat(userPurchaseMid.toFixed(2)),
                  remaining_token: parseFloat(remainingMid.toFixed(2)),
                },
              };
              const updatedValues = { $set: { is_sale: true , is_process: true} };
              await this.salesModel.updateOne({ _id: currentSales[0]._id }, updatedSaleValues);
              await this.transactionService.updateTransactionData(transaction.transactionHash, updatedValues);
              const userRef = ref(
                database,
                firebaseMessages.ICO_TRANSACTIONS + "/" + transaction.transactionHash
              )
              get(userRef)
              .then(async (snapshot) => {
                if (snapshot.exists()) {
                  update(userRef, {
                    lastActive: Date.now(),
                    is_process: true,
                    is_pending: true,
                    is_open: true,
                    is_sale: true,
                  });
                }
              })
            }
          }

        }));
      }

      if (Math.abs(currentTime.diff(this.scheduledTimeMain, 'milliseconds')) <= tolerance) {
        const transactions = await this.transactionModel
          .find({ sale_name: "main-sale", is_sale: false , status :"paid"})
          .exec();
        
        await Promise.all(transactions.map(async transaction => {
          if (transaction.transactionHash) {
            const currentSales = await this.transactionService.getAllSales();
            let userPurchaseMid = parseFloat(transaction.token_cryptoAmount.toFixed(2)) + currentSales[1].user_purchase_token;
            let remainingMid = currentSales[1].total_token - userPurchaseMid;

            if (remainingMid <= 0 || remainingMid - parseFloat(transaction.token_cryptoAmount.toFixed(2)) < 0) {
              return null;
            }
            
            const existingUser = await this.userModel
            .findOne({wallet_address: transaction.user_wallet_address})
            .select("id wallet_address is_verified kyc_completed")

            if (existingUser && existingUser.kyc_completed === false) {
              return null;
            }
            if (
              existingUser && existingUser?.is_verified === 1 &&
              existingUser?.kyc_completed === true 
            ){
              const updatedSaleValues = {
                $set: {
                  user_purchase_token: parseFloat(userPurchaseMid.toFixed(2)),
                  remaining_token: parseFloat(remainingMid.toFixed(2)),
                },
              };
              const updatedValues = { $set: { is_sale: true , is_process: true} };
              await this.salesModel.updateOne({ _id: currentSales[1]._id }, updatedSaleValues);
              await this.transactionService.updateTransactionData(transaction.transactionHash, updatedValues)

              const userRef = ref(
                database,
                firebaseMessages.ICO_TRANSACTIONS + "/" + transaction.transactionHash
              )
              get(userRef)
              .then(async (snapshot) => {
                if (snapshot.exists()) {
                  update(userRef, {
                    lastActive: Date.now(),
                    is_process: true,
                    is_sale: true,
                    is_pending: true,
                    is_open: true,
                  });
                }
              })
            }
           return
          }
        }));
      }
    } catch (error) {
      console.error("Error scheduling task:", error);
      throw error;
    }
  }

  scheduleRecurringCheck() {
    // Schedule a job to call scheduleTargetTimeCron every minute
    schedule.scheduleJob('* * * * *', async () => {
      await this.scheduleTargetTimeCron();
    });
  }
}
