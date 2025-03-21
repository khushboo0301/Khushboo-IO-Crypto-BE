import { Injectable, NotFoundException } from "@nestjs/common";
import { InjectModel } from "@nestjs/mongoose";
import { ITransaction } from "src/interface/transactions.interface";
import { Model } from "mongoose";
import moment from "moment";
import { IUser } from "src/interface/users.interface";
import { ISales } from "src/interface/sales.interface";

@Injectable()
export class TransactionsService {
  constructor(
    @InjectModel("transaction") private transactionModel: Model<ITransaction>,
    @InjectModel("user") private userModel: Model<IUser>,
    @InjectModel("sales") private salesModel: Model<ISales>
  ) {}

  createTransaction(transactionData): Promise<any> {
    const newTransaction = new this.transactionModel(transactionData);
    return newTransaction.save();
  }

  async getSales() {
    const currentDate = moment.utc().format();
    return await this.salesModel
      .findOne({
        $and: [
          { start_sale: { $lte: currentDate } },
          { end_sale: { $gte: currentDate } },
        ],
      })
    .exec();
  }

  async getSalesByName(sale_name: string) {
    return await this.salesModel
      .findOne({
        name : sale_name
      })
    .exec();
  }

  async checkOutsideSales(currentDate) {
    return await this.salesModel
      .findOne({
        $and: [
          { start_sale: { $lte: currentDate } },
          { end_sale: { $gte: currentDate } },
        ],
      })
      .exec();
  }

  async getAllSales() {
    return await this.salesModel.find().exec();
  }

  async getNearestSale() {
    const currentDate = moment.utc();
    const allSales = await this.salesModel.find().exec();

    if (allSales.length === 0) {
      return null; // No sales found
    }

    // Filter out sales that have already ended before the current date
    const validSales = allSales.filter((sale) =>
      moment(sale.end_sale).isAfter(currentDate)
    );
    if (validSales.length === 0) {
      return null; // No valid sales found
    }

    // Calculate the nearest sale date among the valid sales
    const nearestSale = validSales.reduce((nearest, sale) => {
      const startDiff = Math.abs(currentDate.diff(moment(sale.start_sale)));
      const endDiff = Math.abs(currentDate.diff(moment(sale.end_sale)));

      const nearestDiff = Math.min(startDiff, endDiff);
      const currentDiff = nearest
        ? Math.min(
            Math.abs(currentDate.diff(moment(nearest.start_sale))),
            Math.abs(currentDate.diff(moment(nearest.end_sale)))
          )
        : Infinity;

      return nearestDiff < currentDiff ? sale : nearest;
    }, null);
    return nearestSale;
  }

  async checkOutsideNearSales(momentDate) {
    const formattedDate = moment.utc(momentDate);
    //const currentDateFormatted = formattedDate.format("YYYY-MM-DDTHH:mm:ss[Z]");

    const allSales = await this.salesModel.find().exec();

    if (allSales.length === 0) {
      return null; // No sales found
    }

    // Filter out sales that have already ended before the current date
    const validSales = allSales.filter((sale) =>
      moment(sale.end_sale).isAfter(momentDate)
    );
    if (validSales.length === 0) {
      return null; // No valid sales found
    }

    // Calculate the nearest sale date among the valid sales
    const nearestSale = validSales.reduce((nearest, sale) => {
      const startDiff = Math.abs(formattedDate.diff(moment(sale.start_sale)));
      const endDiff = Math.abs(formattedDate.diff(moment(sale.end_sale)));

      const nearestDiff = Math.min(startDiff, endDiff);
      const currentDiff = nearest
        ? Math.min(
            Math.abs(formattedDate.diff(moment(nearest.start_sale))),
            Math.abs(formattedDate.diff(moment(nearest.end_sale)))
          )
        : Infinity;

      return nearestDiff < currentDiff ? sale : nearest;
    }, null);

    return nearestSale;
  }

  async updateTransactionData(
    transactionHash: string,
    fields: any
  ): Promise<any> {
    const updatedvalues = { $set: fields };
    if (transactionHash) {
      const trans = await this.transactionModel.updateOne(
        { transactionHash: transactionHash },
        updatedvalues
      );
      return trans;
    }
    return null;
  }

  async getTransaction(
    address: string,
    page?: number,
    pageSize?: number,
    typeFilter?: any,
    statusFilter?: any
  ): Promise<any> {
    let transactionsQuery = this.transactionModel.find();
    
    if (address) {
      const caseInsensitiveAddress = new RegExp(`^${address}$`, 'i');
      transactionsQuery = transactionsQuery.where({
        user_wallet_address: caseInsensitiveAddress,
      });
    }
  
    // Source filter
    if (typeFilter && typeFilter.length > 0) {
      transactionsQuery = transactionsQuery.where({
        source: { $in: typeFilter },
      });
    }
  
    // Status filter
    if (statusFilter && statusFilter.length > 0) {
      transactionsQuery = transactionsQuery.where({
        status: { $in: statusFilter },
      })
    }
  
    // Pagination
    if (page && pageSize) {
      const skipCount = (page - 1) * pageSize;
      transactionsQuery = transactionsQuery.skip(skipCount).limit(pageSize);
    }
   
    const transactions = await transactionsQuery
      .sort({ created_at: "desc" })
      .exec();
  
    if (!transactions) {
      throw new NotFoundException(`Address #${address} not found`);
    }
    return transactions;
  }

  async getTotalMidCount(name) {
    const midCountResult = await this.transactionModel
      .aggregate([
        {
          $match: {
            status: "paid",
            is_sale: true,
            is_process: true,
            sale_name: name,
          },
        },
        {
          $group: {
            _id: null,
            total: {
              $sum: { $toDouble: "$token_cryptoAmount" },
            },
          },
        },
        {
          $project: {
            _id: 0,
            totalAmount: { $round: ["$total", 2] },
          },
        },
        {
          $group: {
            _id: null,
            totalAmount: { $first: "$totalAmount" },
          },
        },
        {
          $project: {
            _id: 0,
            totalAmount: { $ifNull: ["$totalAmount", 0] },
          },
        },
      ])
      .exec();

    return midCountResult && midCountResult[0]?.totalAmount
      ? midCountResult[0].totalAmount
      : 0;
  }

  async getTotalMidOverAllCount() {
    const midCountResult = await this.transactionModel
      .aggregate([
        {
          $match: {
            status: "paid"
          },
        },
        {
          $group: {
            _id: null,
            total: {
              $sum: { $toDouble: "$token_cryptoAmount" },
            },
          },
        },
        {
          $project: {
            _id: 0,
            totalAmount: { $round: ["$total", 2] },
          },
        },
        {
          $group: {
            _id: null,
            totalAmount: { $first: "$totalAmount" },
          },
        },
        {
          $project: {
            _id: 0,
            totalAmount: { $ifNull: ["$totalAmount", 0] },
          },
        },
      ])
      .exec();

    return midCountResult && midCountResult[0]?.totalAmount
      ? midCountResult[0].totalAmount
      : 0;
  }

  async getTransactionCount(
    address: string,
    typeFilter?: any[],
    statusFilter?: any[]
  ) {
    let transactionsQuery = this.transactionModel.find();
    if (address) {
      const caseInsensitiveAddress = new RegExp(`^${address}$`, 'i');
      transactionsQuery = transactionsQuery.where({
        user_wallet_address: caseInsensitiveAddress,
      });
    }
    if (typeFilter && typeFilter.length > 0) {
      transactionsQuery = transactionsQuery.where({
        source: { $in: typeFilter },
      });
    }
    if (statusFilter && statusFilter.length > 0) {
      transactionsQuery = transactionsQuery.where({
        status: { $in: statusFilter },
      });
    }
   
    const count = await transactionsQuery.countDocuments();
    return count;
  }

  async getSaleGraphTotalToken(
    address: any,
    from_date: any,
    to_date: any
  ): Promise<any> {
    let woToken: {
      status: string;
      is_sale: boolean;
      is_process: boolean;
      created_at: { $gt: any; $lt: any };
      user_wallet_address?: any;
    } = {
      status: "paid",
      is_sale: true,
      is_process: true,
      created_at: { $gt: from_date, $lt: to_date },
    };
    const caseInsensitiveAddress = new RegExp(`^${address}$`, 'i');
    if (address !== null) {
      
      woToken = {
        ...woToken,
        user_wallet_address: caseInsensitiveAddress,
      };
    }

    let totalToken = await this.transactionModel
      .aggregate([
        {
          $match: woToken,
        },
        {
          $group: {
            _id: caseInsensitiveAddress ? "$user_wallet_address" : null,
            totalToken: { $sum: 1 },
          },
        },
      ])
      .exec();
    totalToken =
      totalToken.length && totalToken[0] ? totalToken[0].totalToken : 0;
    return totalToken;
  }

  async getSaleGraphValue(
    address,
    filterType: any,
    from_date: any,
    to_date: any
  ): Promise<any> {
    let woToken: {
      status: string;
      is_sale: boolean;
      is_process: boolean;
      created_at: { $gt: any; $lt: any };
      user_wallet_address?: any;
    } = {
      status: "paid",
      is_sale: true,
      is_process: true,
      created_at: { $gt: from_date, $lt: to_date },
    };
    const caseInsensitiveAddress = new RegExp(`^${address}$`, 'i');
    if (address !== null) {
      woToken = {
        ...woToken,
        user_wallet_address: caseInsensitiveAddress,
      };
    }
    const transactions = await this.transactionModel
      .aggregate([
        {
          $match: woToken,
        },
        {
          $group: {
            _id: {
              $dateToString: {
                format:
                  filterType === "thisWeekDate" ||
                  filterType === "thisMonthDate" ||
                  filterType === "lastWeek" ||
                  filterType === "lastMonth"
                    ? "%Y-%m-%d"
                    : "%Y-%m",
                date: { $toDate: "$created_at" },
              },
            },
            value: { $sum: 1 },
          },
        },
        {
          $addFields: {
            label: "$_id",
          },
        },
        {
          $sort: {
            label: 1,
          },
        },
      ])
      .exec();
    let mainDates = [];

    if (filterType == "thisWeekDate") {
      const thisWeekStart = moment().startOf("week");
      for (let i = 0; i < 7; i++) {
        const currentDate = thisWeekStart
          .clone()
          .add(i, "days")
          .format("YYYY-MM-DD");
        mainDates.push(currentDate);
      }
    }
    if (filterType == "lastWeek") {
      const previousWeekStart = moment().subtract(1, "weeks").startOf("week");
      for (let i = 0; i < 7; i++) {
        const currentDate = previousWeekStart
          .clone()
          .add(i, "days")
          .format("YYYY-MM-DD");
        mainDates.push(currentDate);
      }
    }
    if (filterType == "lastMonth") {
      const startDate = moment().subtract(1, "month").startOf("month");
      const endDate = moment().subtract(1, "month").endOf("month");
      let currentDatePointer = startDate.clone();

      while (currentDatePointer.isSameOrBefore(endDate, "day")) {
        mainDates.push(currentDatePointer.format("YYYY-MM-DD"));
        currentDatePointer.add(1, "day");
      }
    }
    if (filterType == "last3Months") {
      const currentMonth = moment();
      for (let i = 0; i < 3; i++) {
        const previousMonth = currentMonth.clone().subtract(i + 1, "months");
        const formattedMonth = previousMonth.format("YYYY-MM");
        mainDates.push(formattedMonth);
      }
      mainDates = mainDates.reverse();
    }
    if (filterType == "last6Months") {
      const currentMonth = moment();
      for (let i = 0; i < 6; i++) {
        const previousMonth = currentMonth.clone().subtract(i + 1, "months");
        const formattedMonth = previousMonth.format("YYYY-MM");
        mainDates.push(formattedMonth);
      }
      mainDates = mainDates.reverse();
    }
    if (filterType == "lastYear") {
      const currentYear = moment().year();
      for (let i = 0; i < 12; i++) {
        const previousMonth = moment()
          .year(currentYear - 1)
          .month(i);
        const formattedMonth = previousMonth.format("YYYY-MM");
        mainDates.push(formattedMonth);
      }
    }
    if (filterType === "thisMonthDate") {
      // Calculate dates for the current month
      const thisMonthStart = moment().startOf("month");
      const thisMonthEnd = moment().endOf("month");

      let currentDatePointer = thisMonthStart.clone();
      while (currentDatePointer.isSameOrBefore(thisMonthEnd, "day")) {
        mainDates.push(currentDatePointer.format("YYYY-MM-DD"));
        currentDatePointer.add(1, "day");
      }
    }
    if (filterType === "thisYearDate") {
      const currentYear = moment().year();
      for (let i = 0; i < 12; i++) {
        const thisMonth = moment().year(currentYear).month(i);
        const formattedMonth = thisMonth.format("YYYY-MM");
        mainDates.push(formattedMonth);
      }
    }

    let data = transactions?.map((trans) => {
      let key = trans.label;
      return { [key]: trans.value };
    });
    data = { ...Object.assign({}, ...data) };

    const result = mainDates?.map((d) => {
      if (data[d]) {
        return { label: d, value: data[d] };
      } else {
        return { label: d, value: 0 };
      }
    });
    return result;
  }

  async getLineGraphTotalToken(
    address: any,
    from_date: any,
    to_date: any
  ): Promise<any> {
    let woToken: {
      status: string;
      is_sale: boolean;
      is_process: boolean;
      created_at: { $gt: any; $lt: any };
      user_wallet_address?: any;
    } = {
      status: "paid",
      is_sale: true,
      is_process: true,
      created_at: { $gt: from_date, $lt: to_date },
    };
    const caseInsensitiveAddress = new RegExp(`^${address}$`, 'i');
    if (address !== null) {
      woToken = {
        ...woToken,
        user_wallet_address: caseInsensitiveAddress,
      };
    }

    let totalToken = await this.transactionModel
      .aggregate([
        {
          $match: woToken,
        },
        {
          $group: {
            _id: caseInsensitiveAddress ? "$wallet_address" : null,
            totalToken: { $sum: 1 },
          },
        },
      ])
      .exec();
    totalToken =
      totalToken.length && totalToken[0] ? totalToken[0].totalToken : 0;
    return totalToken;
  }

  async getLineGraphValue(
    address,
    filterType: any,
    from_date: any,
    to_date: any
  ): Promise<any> {
    let woToken: {
      status: string;
      is_sale: boolean;
      is_process: boolean;
      created_at: { $gt: any; $lt: any };
      user_wallet_address?: any;
    } = {
      status: "paid",
      is_sale: true,
      is_process: true,
      created_at: { $gt: from_date, $lt: to_date },
    };
    const caseInsensitiveAddress = new RegExp(`^${address}$`, 'i');
    if (address !== null) {
      woToken = {
        ...woToken,
        user_wallet_address: caseInsensitiveAddress,
      };
    }
    const transactions = await this.transactionModel
      .aggregate([
        {
          $match: woToken,
        },
        {
          $group: {
            _id: {
              $dateToString: {
                format:
                  filterType === "thisWeekDate" ||
                  filterType === "thisMonthDate" ||
                  filterType === "thisMonthDate" ||
                  filterType === "lastWeek" ||
                  filterType === "lastMonth"
                    ? "%Y-%m-%d"
                    : "%Y-%m",
                date: { $toDate: "$created_at" },
              },
            },
            value: { $sum: 1 },
          },
        },
        {
          $addFields: {
            label: "$_id",
          },
        },
        {
          $sort: {
            label: 1,
          },
        },
      ])
      .exec();
    const mainDates = [];

    if (filterType == "thisWeekDate") {
      const thisWeekStart = moment().subtract(1, "weeks").startOf("week");
      for (let i = 0; i < 7; i++) {
        const currentDate = thisWeekStart
          .clone()
          .add(i, "days")
          .format("YYYY-MM-DD");
        mainDates.push(currentDate);
      }
    }
    if (filterType == "lastWeek") {
      const previousWeekStart = moment().subtract(2, "weeks").startOf("week");
      for (let i = 0; i < 7; i++) {
        const currentDate = previousWeekStart
          .clone()
          .add(i, "days")
          .format("YYYY-MM-DD");
        mainDates.push(currentDate);
      }
    }
    if (filterType == "lastMonth") {
      const startDate = moment().subtract(2, "month").startOf("month");
      const endDate = moment().subtract(2, "month").endOf("month");
      let currentDatePointer = startDate.clone();

      while (currentDatePointer.isSameOrBefore(endDate, "day")) {
        mainDates.push(currentDatePointer.format("YYYY-MM-DD"));
        currentDatePointer.add(1, "day");
      }
    }
    if (filterType == "last3Months") {
      const currentMonth = moment();
      for (let i = 3; i < 6; i++) {
        const previousMonth = currentMonth.clone().subtract(i + 1, "months");
        const formattedMonth = previousMonth.format("YYYY-MM");
        mainDates.push(formattedMonth);
      }
    }
    if (filterType == "last6Months") {
      const currentMonth = moment();
      for (let i = 6; i < 12; i++) {
        const previousMonth = currentMonth.clone().subtract(i + 1, "months");
        const formattedMonth = previousMonth.format("YYYY-MM");
        mainDates.push(formattedMonth);
      }
    }
    if (filterType == "lastYear") {
      const currentYear = moment().year();
      for (let i = 0; i < 12; i++) {
        const previousMonth = moment()
          .year(currentYear - 2)
          .month(i);
        const formattedMonth = previousMonth.format("YYYY-MM");
        mainDates.push(formattedMonth);
      }
    }
    if (filterType === "thisMonthDate") {
      // Calculate dates for the current month
      const thisMonthStart = moment().startOf("month");
      const thisMonthEnd = moment().endOf("month");
      let currentDatePointer = thisMonthStart.clone();
      while (currentDatePointer.isSameOrBefore(thisMonthEnd, "day")) {
        mainDates.push(currentDatePointer.format("YYYY-MM-DD"));
        currentDatePointer.add(1, "day");
      }
    }
    if (filterType === "thisYearDate") {
      const currentYear = moment().year();
      for (let i = 0; i < 12; i++) {
        const thisMonth = moment().year(currentYear).month(i);
        const formattedMonth = thisMonth.format("YYYY-MM");
        mainDates.push(formattedMonth);
      }
    }

    let data = transactions?.map((trans) => {
      let key = trans.label;
      return { [key]: trans.value };
    });
    data = { ...Object.assign({}, ...data) };

    const result = mainDates?.map((d) => {
      if (data[d]) {
        return { label: d, value: data[d] };
      } else {
        return { label: d, value: 0 };
      }
    });
    return result;
  }

  async getTransactionByOredrId(orderId: string): Promise<any> {
    const transaction = this.transactionModel
      .findOne({ transactionHash: orderId })
      .exec();
    return transaction;
  }

  async getPaidTransactionByOrderId(orderId: string, status: string): Promise<any> {
    try {
      const transaction = await this.transactionModel.findOne({
        transactionHash: orderId,
        status: status,
      }).exec();
      
      return transaction;
    } catch (error) {
      console.error(`Error finding transaction with orderId: ${orderId} and status: ${status}`, error);
      throw error;
    }
  }

  async getTokenCount(address?: string) {
    let whereQuery: {
      status: any;
      is_sale: boolean;
      is_process: boolean;
      user_wallet_address?: any;
    } = {
      status: "paid",
      is_sale: true,
      is_process: true,
    };
    const caseInsensitiveAddress = new RegExp(`^${address}$`, 'i');
    if (address) {
      whereQuery = {
        ...whereQuery,
        user_wallet_address: caseInsensitiveAddress,
      };
    }
    const tokenCountResult = await this.transactionModel
      .aggregate([
        {
          $match: whereQuery,
        },
        {
          $group: {
            _id: "$price_currency",
            total: {
              $sum: { $toDouble: "$token_cryptoAmount" },
            },
          },
        },
      ])
      .exec();
    return tokenCountResult;
  }

  async getUsdtCount(address?: string) {
    let whereQuery: {
      status: any;
      is_sale: boolean;
      is_process: boolean;
      user_wallet_address?: any;
    } = {
      status: "paid",
      is_sale: true,
      is_process: true
    };
    const caseInsensitiveAddress = new RegExp(`^${address}$`, 'i');
    if (address) {
      whereQuery = {
        ...whereQuery,
        user_wallet_address: caseInsensitiveAddress,
      };
    }
    const tokenCountResult = await this.transactionModel
      .aggregate([
        {
          $match: whereQuery,
        },
        {
          $group: {
            _id: "$price_currency",
            total: {
              $sum: { $toDouble: "$price_amount" },
            },
          },
        },
      ])
      .exec();
    return tokenCountResult;
  }
}
