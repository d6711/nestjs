import { Body, Controller, Get, Post, UseGuards } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { ValidationPipe } from "src/pipes/validation.pipe";
import { AuthRequest } from "./auth.request.dto";
import { AuthGuard } from "@nestjs/passport";

@Controller("/v1/auth")
export class AuthController {
    constructor(private readonly authService: AuthService) {}

    @UseGuards(AuthGuard("local"))
    @Post("/login")
    login(@Body(new ValidationPipe()) request: AuthRequest): unknown {
        try {
            console.log(request);
            return this.authService.authenticate(request);
        } catch (error) {
            console.error("Errors:", error);
        }
    }
}
