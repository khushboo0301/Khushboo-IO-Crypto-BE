import { Module, MiddlewareConsumer} from "@nestjs/common";
import { MongooseModule } from "@nestjs/mongoose";
import { AppController } from "./app.controller";
import { AppService } from "./app.service";
import { UsersController } from "./controller/user/users.controller";
import { AuthController } from "./controller/auth/auth.controller";
import { UserSchema } from "./schema/user.schema";
import { UserService } from "./service/user/users.service";
import { EmailService } from "./service/email/email.service";
import { AuthenticateMiddleware } from "./middleware/authenticate.middleware";
import { ConfigModule, ConfigService  } from "@nestjs/config";
import configuration from "./config/configuration";
import { TokenService } from "./service/token/token.service";
import { TokenSchema } from "./schema/token.schema";
import { SalesSchema } from "./schema/sales.schema";
import { TransactionsController } from "./controller/transaction/transactions.controller";
import { TransactionsService } from "./service/transaction/transactions.service";
import { TransactionSchema } from "./schema/transaction.schema";
import { ThrottlerModule, ThrottlerGuard } from "@nestjs/throttler";
import { APP_GUARD } from "@nestjs/core";
import { CustomThrottleMiddleware } from "./middleware/custom-throttle.middleware";
import { ScheduleModule } from '@nestjs/schedule';
import { MailerModule } from "@nestjs-modules/mailer";
import { join } from "path";
import { HandlebarsAdapter } from "@nestjs-modules/mailer/dist/adapters/handlebars.adapter";
import { ServeStaticModule } from '@nestjs/serve-static';
import { JwtModule } from '@nestjs/jwt';
import { CacheModule } from '@nestjs/cache-manager';

@Module({
  imports: [
    MongooseModule.forRoot("mongodb://127.0.0.1:27017/ico"),
    MongooseModule.forFeature([{ name: "user", schema: UserSchema }]),
    MongooseModule.forFeature([{ name: "sales", schema: SalesSchema }]),
    MongooseModule.forFeature([{ name: "token", schema: TokenSchema }]),
    MongooseModule.forFeature([
      { name: "transaction", schema: TransactionSchema },
    ]),
    CacheModule.register({
      ttl: 5, // Cache time-to-live in seconds
      max: 100, // Maximum number of items in cache
    }),
    ConfigModule.forRoot({
      isGlobal: true,
      load: [configuration],
    }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('ICO_JWT_EMAIL_SECRET'),
        signOptions: { expiresIn: '1h' },
      }),
    }),
    ServeStaticModule.forRoot({
      rootPath: join(__dirname, '..', 'public'),
    }),
    MailerModule.forRoot({
      transport: {
        host: process.env.ICO_MAIL_HOST,
        port: parseInt(process.env.ICO_MAIL_PORT, 10),
        secure: false,
        auth: {
          user: process.env.ICO_MAIL_USER,
          pass: process.env.ICO_MAIL_PASSWORD,
        },
      },
      template: {
        dir: join(__dirname, "mails"),
        adapter: new HandlebarsAdapter(),
        options: {
          strict: true,
        },
      },
      defaults: {
        from: process.env.ICO_MAIL_FROM_MAIL,
      },
    }),
    ThrottlerModule.forRoot({
      ttl: 5,
      limit: 5,
    }),
    ScheduleModule.forRoot(),
  ],
  controllers: [
    AppController,
    UsersController,
    AuthController,
    TransactionsController,
  ],
  providers: [
    AppService,
    UserService,
    TokenService,
    EmailService,
    TransactionsService,
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard,
    },
  ],
})

export class AppModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(AuthenticateMiddleware).forRoutes("/users", "/transactions");
    consumer.apply(CustomThrottleMiddleware).forRoutes(
      "/users/updateAccountSettings",
      "/users/generate2FASecret",
      "/users/updateKyc",
      "/users/validateTOTP",
      "/transactions/createOrder",
      "/users/verify"
    );
  }
}
