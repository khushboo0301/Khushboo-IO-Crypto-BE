import {
  Body,
  Controller,
  Get,
  HttpStatus,
  Param,
  Post,
  Put,
  Res,
  Req,
} from "@nestjs/common";
import moment from "moment";
import { TransactionsService } from "src/service/transaction/transactions.service";
import { UserService } from "src/service/user/users.service";
import { InjectModel } from "@nestjs/mongoose";
import { Model } from "mongoose";
import { ITransaction } from "src/interface/transactions.interface";
import { SkipThrottle } from "@nestjs/throttler";
import { ISales } from "src/interface/sales.interface";
import { IUser } from "src/interface/users.interface";
import { MailerService } from "@nestjs-modules/mailer";
import { ConfigService } from "@nestjs/config";
import { EmailService } from "src/service/email/email.service";

@SkipThrottle()
@Controller("transactions")
export class TransactionsController {
  constructor(
    private readonly transactionService: TransactionsService,
    private readonly userService: UserService,
    private readonly mailerService: MailerService,
    private readonly configService: ConfigService,
    private readonly emailService: EmailService,
    @InjectModel("transaction") private transactionModel: Model<ITransaction>,
    @InjectModel("sales") private salesModel: Model<ISales>,
    @InjectModel("user") private usersModel: Model<IUser>
  ) {}

  /**
   *
   * @param req
   * @param response
   * @returns
   */
  @SkipThrottle(false)
  @Post("/verifyToken")
  async verifyToken(@Req() req: any, @Res() response) {
    try {
      const { wallet_address, cryptoAmount, amount } = req.body;

      // Validate required fields
      const missingFields = ["Wallet address", "Crypto amount", "Amount"].filter(
        (field, index) => ![wallet_address, cryptoAmount, amount][index]
      );

      if (missingFields.length) {
        return response.status(HttpStatus.BAD_REQUEST).json({
          status: "failure",
          message: `${missingFields.join(", ")} is missing`,
        });
      }

      // Fetch user and validate
      const user = await this.userService.getFindbyAddress(wallet_address);
      if (!user) {
        return response.status(HttpStatus.BAD_REQUEST).json({
          status: "failure",
          message: "Wallet address does not exist",
        });
      }

      if (!user.kyc_completed || user.is_verified !== 1) {
        return response.status(HttpStatus.BAD_REQUEST).json({
          status: "failure",
          message: user.kyc_completed
            ? "Your KYC is not verified by admin"
            : "Please complete your KYC to buy tokens",
        });
      }

      if (user.status === "Suspend") {
        return response.status(HttpStatus.BAD_REQUEST).json({
          status: "failure",
          message: "Can't buy tokens, you are suspended by admin.",
        });
      }

      // Fetch sales data and validate token availability
      const sales = await this.transactionService.getSales();
      const calculatedCryptoAmount = parseFloat((amount / (sales?.amount || 0)).toFixed(2));

      if (calculatedCryptoAmount !== parseFloat(cryptoAmount.toFixed(2))) {
        return response.status(HttpStatus.BAD_REQUEST).json({
          status: "failure",
          message: "Invalid crypto amount calculation.",
        });
      }

      const remainingTokens = sales.total_token - sales.user_purchase_token;
      if (remainingTokens <= 0) {
        return response.status(HttpStatus.BAD_REQUEST).json({
          status: "failure",
          message: "Token balance is empty",
        });
      }

      if (remainingTokens < cryptoAmount) {
        return response.status(HttpStatus.BAD_REQUEST).json({
          status: "failure",
          message: "Not enough tokens available for purchase",
        });
      }

      // Success response
      return response.status(HttpStatus.OK).json({
        status: "success",
        message: "Token verification successful",
      });
    } catch (err) {
      console.error("Error in verifyToken:", err);
      return response.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
        status: "failure",
        message: "An error occurred",
        error: err.message,
      });
    }
  }


  /**
   * This API endpoint is used to create an order for purchasing tokens.
   * @param req
   * @param response
   * @returns
   */
  @SkipThrottle(false)
  @Post("/createOrder")
  async createOrder(@Req() req: any, @Res() response) {
    try {
      const {
        user_wallet_address,
        transactionHash,
        network,
        cryptoAmount,
        amount,
        gasUsed,
        effectiveGasPrice,
        cumulativeGasUsed,
        blockNumber,
        blockHash,
        status,
      } = req.body;

      // Validate required fields
      const requiredFields = {
        user_wallet_address: "Wallet address",
        transactionHash: "Transaction ID",
        network: "Network",
        cryptoAmount: "Crypto amount",
        amount: "Amount",
      };
      const missingFields = Object.entries(requiredFields)
        .filter(([key]) => !req.body[key])
        .map(([, value]) => value);

      if (missingFields.length) {
        return response.status(HttpStatus.BAD_REQUEST).json({
          status: "failure",
          message: `${missingFields.join(", ")} is missing`,
        });
      }

      const user = await this.userService.getFindbyAddress(user_wallet_address);
      if (!user) {
        return response.status(HttpStatus.BAD_REQUEST).json({
          status: "failure",
          message: "Wallet address does not exist",
        });
      }

      if (!user.kyc_completed || user.is_verified !== 1) {
        const message = user.kyc_completed
          ? "Your KYC is not verified by admin"
          : "Please complete your KYC to Buy Token";
        return response.status(HttpStatus.BAD_REQUEST).json({
          status: "failure",
          message,
        });
      }

      if (user.status === "Suspend") {
        return response.status(HttpStatus.BAD_REQUEST).json({
          status: "failure",
          message: "Can't Buy Token, You are Suspended by Admin.",
        });
      }

      const sales = await this.transactionService.getSales();
      const userPurchaseMid = parseFloat(cryptoAmount.toFixed(2)) + sales.user_purchase_token;
      const calculatedCryptoAmount = amount / (sales.amount || 0);

      if (calculatedCryptoAmount.toFixed(2) !== cryptoAmount) {
        return response.status(HttpStatus.BAD_REQUEST).json({
          status: "failure",
          message: "Invalid crypto amount calculation.",
        });
      }

      const remainingMid = sales.total_token - userPurchaseMid;
      if (remainingMid <= 0) {
        return response.status(HttpStatus.BAD_REQUEST).json({
          status: "failure",
          message: "Token Balance is empty",
        });
      }

      if (remainingMid - cryptoAmount < 0) {
        return response.status(HttpStatus.BAD_REQUEST).json({
          status: "failure",
          message: "All Tokens are sold",
        });
      }
      const receiver_address = this.configService.get("receiver_address");
      const transactionData = {
        transactionHash,
        status: status || "pending",
        user_wallet_address,
        receiver_wallet_address: receiver_address,
        network,
        price_currency: "USDT",
        is_sale: true,
        is_process: false,
        price_amount: amount,
        token_cryptoAmount: calculatedCryptoAmount,
        gasUsed,
        effectiveGasPrice,
        cumulativeGasUsed,
        blockNumber,
        blockHash,
        created_at: moment.utc().format(),
        source: user?.referred_by ? "referral" : "purchase",
        sale_name: sales.name,
        sale_type: "website",
      };

      const transaction = await this.transactionService.createTransaction(transactionData);

      // Send email notifications
      if (user && user.email && user.email_verified) {
        const emailContext = {
          formattedDate: moment().format("dddd, MMMM D, YYYY"),
          order_id: `OrderID: ${transaction._id}`,
          transactionHash: `TransactionHash: ${transaction.transactionHash}`,
          price_amount: `Amount: ${amount}`,
        };

        const emailDetails =
          transaction.status === "pending"
            ? {
                heading: "Thank you for your contribution!",
                para1: `You have requested to purchase ${network} token.Your order has been received and is now being waiting for payment. You order details are show below for your reference.`,
                para2: `If you have not made the payment yet, please send your payment to the following address: ${receiver_address}`,
                para3: `Your order will be processed within 6 hours from the receipt of payment and token balance will appear in your account as soon as we have confirmed your payment.`,
                para4: "Feel free to contact us if you have any questions.",
                order_details: "Order Details:",
                title: "Token Purchase - Order Placed by Online Gateway",
                mailSubject: `[Middn.io] Order placed for Token Purchase #${user._id}`
              }
            : {
                greeting: `Hello ${user.fname || "John Doe"}`,
                para1: `We noticed that you attempted to purchase ${network} however we have not received your payment of ${amount} via Meta mask for ${transaction.token_cryptoAmount} Token.`,
                para5: "It looks like your payment gateway has been rejected the transaction.",
                para3: "If you want to pay manually, please feel free to contact us via support@middn.com",
                order_details: "Order Details:",
                receiver_address: receiver_address,
                title: "Token Purchase - Order Unpaid/Rejected by Gateway",
                mailSubject: `[Middn.io] Unpaid Order Canceled #${user._id}`
              };

        const globalContext = { ...emailContext, ...emailDetails };
        await this.emailService.sendVerificationEmail(user, globalContext, emailDetails.mailSubject);
      }

      // Update sales data
      await this.salesModel.updateOne(
        { _id: sales._id },
        { $set: { remaining_token: remainingMid } }
      );

      await this.transactionService.updateTransactionData(transaction.transactionHash, {
        is_process: true,
      });

      return response.status(HttpStatus.OK).json({
        message: "Order Created Successfully",
        transaction: { transactionHash: transaction.transactionHash },
      });
    } catch (error) {
      console.error("Error in createOrder:", error);
      return response.status(HttpStatus.BAD_REQUEST).json({
        message: "Something went wrong",
      });
    }
  }

  /**
   *
   * @param req
   * @param response
   * @returns
   */
  @SkipThrottle(false)
  @Put("/updateOrder")
  async updateOrder(@Req() req: any, @Res() response) {
    try {
      const { status, transactionHash, amount, network } = req.body;

      const transData = {
        status,
        paid_at: moment.utc().format(),
        is_process: true,
      };
      await this.transactionService.updateTransactionData(transactionHash, transData);

      const userTrans = await this.transactionService.getTransactionByOredrId(transactionHash);
      const sales = await this.transactionService.getSales();

      if (status === "paid") {
        await this.handlePaidTransaction(userTrans, sales, req.body, response);
      } else {
        await this.handleFailedTransaction(userTrans, sales, response);
      }
    } catch (error) {
      return response.status(HttpStatus.BAD_REQUEST).json({
        message: "Something went wrong",
      });
    }
  }

  private async handlePaidTransaction(userTrans, sales, requestBody, response) {
    const referredFromUser = await this.usersModel.findOne({
      wallet_address: userTrans.user_wallet_address,
    });
    const referredWalletAddress = referredFromUser?.referred_by;

    const totalUserTrans = await this.transactionModel.countDocuments({
      user_wallet_address: userTrans.user_wallet_address,
      status: "paid",
      is_sale: true,
    });

    // Handle first paid transaction and referral logic
    if (userTrans.status === "paid" && totalUserTrans === 1 && referredWalletAddress) {
      await this.processReferralTransaction(
        userTrans,
        sales,
        referredWalletAddress,
        response
      );
    } else {
      await this.processDirectSale(userTrans, sales, referredFromUser, requestBody, response);
    }
  }

  private async processReferralTransaction(userTrans, sales, referredWalletAddress, response) {
    const priceAmount = Math.round(userTrans.price_amount * 0.1);
    const cryptoAmount = Math.round(userTrans.token_cryptoAmount * 0.1);

    const referredByUserDetails = await this.usersModel.findOne({
      _id: new Object(referredWalletAddress),
    });

    const orderDocument = {
      status: "paid",
      sale_name: userTrans.sale_name,
      sale_type: userTrans.sale_type,
      is_sale: !!sales,
      is_process: true,
      price_currency: "USDT",
      price_amount: priceAmount,
      network: userTrans.network,
      created_at: moment.utc().format(),
      user_wallet_address: referredByUserDetails?.wallet_address,
      token_cryptoAmount: cryptoAmount.toFixed(2),
      source: "referral",
    };
    const trans = await this.transactionService.createTransaction(orderDocument);

    if (trans) {
      const updatedSaleValues = {
        $set: {
          user_purchase_token:
            Number(sales?.user_purchase_token) + parseFloat(cryptoAmount.toFixed(2)),
          remaining_token:
            Number(sales?.remaining_token) - parseFloat(cryptoAmount.toFixed(2)),
        },
      };

      await this.salesModel.updateOne({ _id: sales?._id }, updatedSaleValues);
      await this.transactionService.updateTransactionData(userTrans.transactionHash, {
        is_process: true,
      });

      return response.status(HttpStatus.OK).json({ message: "success" });
    }
  }

  private async processDirectSale(userTrans, sales, referredFromUser, requestBody, response) {
    const userPurchased = Number(sales?.user_purchase_token) + Number(userTrans.token_cryptoAmount);
    const updatedSaleValues = { $set: { user_purchase_token: userPurchased.toFixed(2) } };

    await this.salesModel.updateOne({ _id: sales?._id }, updatedSaleValues);

    if (referredFromUser?.email && referredFromUser.email_verified) {
      const globalContext = this.getEmailContext(referredFromUser, userTrans, requestBody);

      const mailSubject = `[Middn.io] Token Purchase Successful - Order #${userTrans._id}`;
      await this.emailService.sendVerificationEmail(referredFromUser, globalContext, mailSubject);
    }

    await this.transactionService.updateTransactionData(userTrans.transactionHash, {
      is_process: true,
    });

    return response.status(HttpStatus.OK).json({ message: "success" });
  }

  private async handleFailedTransaction(userTrans, sales, response) {
    const userPurchased = Number(sales?.remaining_token) + Number(userTrans.token_cryptoAmount);
    const updatedSaleValues = { $set: { remaining_token: userPurchased } };

    await this.salesModel.updateOne({ _id: sales?._id }, updatedSaleValues);
    await this.transactionService.updateTransactionData(userTrans.transactionHash, {
      is_process: true,
    });

    return response.status(HttpStatus.OK).json({ message: "failed" });
  }

  private getEmailContext(referredFromUser, userTrans, requestBody) {
    return {
      formattedDate: moment().format("dddd, MMMM D, YYYY"),
      heading: `Congratulations ${
        referredFromUser?.fname
          ? `${referredFromUser.fname} ${referredFromUser.lname}`
          : "John Doe"
      }, your order has been processed successfully.`,
      para1: `Thank you for your contribution and purchase of our ${requestBody?.network} Token!`,
      para2: `Your token balances now appear in your account. Please login into your and check your balance.  Please note that, we will send smart contract end of the token sales.`,
      para3: "Feel free to contact us if you have any questions.",
      order_details: "Order Details:",
      order_id: `OrderID: ${userTrans?._id}`,
      transactionHash: `TransactionHash: ${userTrans?.transactionHash}`,
      price_amount: `Amount: ${requestBody?.amount}`,
      title: "Token Purchase - Order Successful",
    };
  }

  /**
   *
   * @param req
   * @param response
   * @returns
   */
  @Get("/checkCurrentSale")
  async checkCurrentSale(@Req() req: any, @Res() response) {
    const sales = await this.transactionService.getSales();
    if (sales) {
      return response.status(HttpStatus.OK).json({
        message: "Sales get successfully",
        sales: sales,
      });
    } else {
      return response.status(HttpStatus.OK).json({
        message: "Sale Not Found",
        sales: null,
      });
    }
  }

  /**
   *
   * @param req
   * @param response
   * @returns
   */
  @Get("/getPurchasedToken")
  async getPurchasedToken(@Req() req: any, @Res() response) {
    const sales = await this.transactionService.getSales();
    if (sales) {
      return response.status(HttpStatus.OK).json({
        message: "Sales get successfully",
        sales: sales,
      });
    } else {
      return response.status(HttpStatus.OK).json({
        message: "Sale Not Found",
        sales: null,
      });
    }
  }

  /**
   * This API endpoint retrieves transactions based on specified filters like type and status.
   * @param req
   * @param response
   * @param body
   * @returns
   */
  @Post("/getTransactions")
  async getTransactions(
    @Req() req,
    @Res() response,
    @Body() body: { typeFilter?: any[]; statusFilter?: any[] }
  ) {
    try {
      const page = req.query.page ? req.query.page : 1;
      const pageSize = req.query.pageSize ? req.query.pageSize : 10;
      const typeFilter = req.body.typeFilter;
      const statusFilter = req.body.statusFilter;
      const verifiedAddress = req.headers.authData?.verifiedAddress;

      if (!verifiedAddress) {
        return response.status(HttpStatus.BAD_REQUEST).json({
          message: "Verified address is missing",
        });
      }

      // Fetch transactions and count concurrently
      const [transactions, transactionsCount] = await Promise.all([
        this.transactionService.getTransaction(
          verifiedAddress,
          Number(page),
          Number(pageSize),
          typeFilter,
          statusFilter
        ),
        this.transactionService.getTransactionCount(
          verifiedAddress,
          typeFilter,
          statusFilter
        ),
      ]);

      return response.status(HttpStatus.OK).json({
        message: "Transactions retrieved successfully",
        transactions,
        totalTransactionsCount: transactionsCount,
      });
    } catch (error) {
      console.error("Error in getTransactions:", error);
      return response.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
        message: "Something went wrong",
      });
    }
  }

  /**
   * This API endpoint retrieves the total token count for each supported currency (GBP, AUD, EUR)
   * @param req
   * @param response
   * @returns
   */
  @Get("/getTokenCount")
  async getTokenCount(@Req() req: any, @Res() response) {
    try {
      const verifiedAddress = req.headers.authData?.verifiedAddress;

      if (!verifiedAddress) {
        return response.status(HttpStatus.BAD_REQUEST).json({
          message: "Verified address is missing",
        });
      }
      const [currencyData, usdtData] = await Promise.all([
        this.transactionService.getTokenCount(verifiedAddress),
        this.transactionService.getUsdtCount(verifiedAddress),
      ]);

      const formatData = (data) =>
        Object.assign(
          {},
          ...data.map((obj) => ({ [obj._id]: parseFloat(obj.total.toFixed(2)) || 0 }))
        );

      const formattedCurrencyData = formatData(currencyData);
      const formattedUsdtData = formatData(usdtData);

      const totalTokenCount = {
        totalUserCount: formattedCurrencyData["USDT"] || 0,
        totalUsdtCount: formattedUsdtData["USDT"] || 0,
      };

      return response.status(HttpStatus.OK).json({
        message: "Fetched total token count successfully",
        totalTokenCount,
      });
    } catch (error) {
      console.error("Error in getTokenCount:", error);
      return response.status(HttpStatus.INTERNAL_SERVER_ERROR).json({
        message: "Something went wrong",
      });
    }
  }

  /**
   * This API endpoint retrieves the sale graph values and total token count within a specified date range
   * @param req
   * @param response
   * @returns
   */
  @Post("/getSaleGrapthValues")
  async getSaleGrapthValues(@Req() req: any, @Res() response) {
    try {
      const option = req.body.option;
      const from_date = req.body.from_date;
      const to_date = req.body.to_date;
      const transactionData = await this.transactionService.getSaleGraphValue(
        req.headers.authData.verifiedAddress,
        option,
        from_date,
        to_date
      );
      const totalToken = await this.transactionService.getSaleGraphTotalToken(
        req.headers.authData.verifiedAddress,
        from_date,
        to_date
      );
      if (transactionData) {
        return response.status(HttpStatus.OK).json({
          message: "get TotalAmount Amount Successfully",
          transactionData: transactionData,
          totalToken: totalToken,
        });
      } else {
        return response.status(HttpStatus.BAD_REQUEST).json({
          message: "Something went wrong",
        });
      }
    } catch (err) {
      return response.status(HttpStatus.BAD_REQUEST).json({
        message: "Something went wrong",
      });
    }
  }

  /**
   * This API endpoint retrieves the line graph values and total token count within a specified date range
   * @param req
   * @param response
   * @returns
   */
  @Post("/getLineGrapthValues")
  async getLineGrapthValues(@Req() req: any, @Res() response) {
    try {
      const option = req.body.option;
      const from_date = req.body.from_date;
      const to_date = req.body.to_date;
      const transactionData = await this.transactionService.getLineGraphValue(
        req.headers.authData.verifiedAddress,
        option,
        from_date,
        to_date
      );
      const totalToken = await this.transactionService.getLineGraphTotalToken(
        req.headers.authData.verifiedAddress,
        from_date,
        to_date
      );
      if (transactionData) {
        return response.status(HttpStatus.OK).json({
          message: "get TotalAmount Amount Successfully",
          transactionData: transactionData,
          totalToken: totalToken,
        });
      } else {
        return response.status(HttpStatus.BAD_REQUEST).json({
          message: "Something went wrong",
        });
      }
    } catch (err) {
      return response.status(HttpStatus.BAD_REQUEST).json({
        message: "Something went wrong",
      });
    }
  }

  /**
   * This API endpoint retrieves transaction data based on the provided order ID.
   * @param req
   * @param response
   * @param param
   * @returns
   */
  @Get("/getTransactionByOrderId/:orderId")
  async getTransactionByOrderId(
    @Req() req: any,
    @Res() response,
    @Param() param: { orderId: string }
  ) {
    try {
      const transactionData =
        await this.transactionService.getTransactionByOredrId(param.orderId);
      if (transactionData) {
        return response.status(HttpStatus.OK).json({
          message: "Transaction fetch Successfully",
          transactionData: transactionData,
        });
      } else {
        return response.status(HttpStatus.BAD_REQUEST).json({
          message: "Something went wrong",
        });
      }
    } catch (err) {
      return response.status(HttpStatus.BAD_REQUEST).json({
        message: "Something went wrong",
      });
    }
  }
}
