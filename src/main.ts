import { NestFactory } from "@nestjs/core";
import { AppModule } from "./app.module";
import { ValidationPipe } from "@nestjs/common";
import * as express from "express";
import { CustomThrottlingExceptionFilter } from "./exceptions/custom-throttling.exception";

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { cors: true });
  app.enableCors();
  app.useGlobalPipes(new ValidationPipe());
  app.use("/uploads", express.static("uploads"));
  app.useGlobalFilters(new CustomThrottlingExceptionFilter());
  await app.listen(3000);
}
bootstrap();
