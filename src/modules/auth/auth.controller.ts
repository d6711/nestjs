import { Body, Controller, Get, HttpStatus, Post, Req } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { ValidationPipe } from "src/pipes/validation.pipe";
import { AuthRequest } from "./auth.request.dto";
import { ApiResponse, TApiResponse } from "src/common/bases/api-response";
import { ILoginResponse } from "./auth.interface";
import { Request } from "express";
import { UserWithoutPassword } from "../user/user.interface";

const GUARD = 'ADMIN'

@Controller("/v1/auth")
export class AuthController {
  constructor(private readonly authService: AuthService) { }


  @Post("login")
  async login(
    @Body(new ValidationPipe()) authRequest: AuthRequest,
    @Req() request: Request
  ): Promise<TApiResponse<ILoginResponse>> {
    //generic
    const response = await this.authService.authenticate(authRequest, request, GUARD);
    return ApiResponse.ok(response, "Đăng nhập thành công", HttpStatus.OK);
  }

  // @Get('me')
  // async me(@Req request: Request): Promise<TApiResponse<UserWithoutPassword>> {
  //   const response = await this.authService.getMe()
  //   return ApiResponse.ok()
  // }
}
