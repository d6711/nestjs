import { Module } from "@nestjs/common";
import { AuthController } from "./auth.controller";
import { AuthService } from "./auth.service";
import { PrismaService } from "../prisma/prisma.service";
import { JwtModule } from "@nestjs/jwt";
import { jwtConstants } from "./auth.constants";
import { CacheModule } from "@nestjs/cache-manager";
import { PassportModule } from "@nestjs/passport";

@Module({
  imports: [
    PassportModule,
    JwtModule.register({
      global: true,
      secret: jwtConstants.secret,
      signOptions: { expiresIn: "5m" }
    })
  ],
  controllers: [AuthController],
  providers: [AuthService, PrismaService]
})
export class AuthModule { }
