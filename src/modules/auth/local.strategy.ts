import { Strategy } from "passport-local";
import { PassportStrategy } from "@nestjs/passport";
import { HttpException, HttpStatus, Injectable } from "@nestjs/common";
import { AuthService } from "./auth.service";
import { ApiResponse } from "src/common/bases/api-response";

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
    constructor(private authService: AuthService) {
        super({
            usernameField: "email",
            passwordField: "password"
        });
    }

    async validate(email: string, password: string): Promise<any> {
        const user = await this.authService.validateUser(email, password);
        if (!user) {
            const response = ApiResponse.error(
                "Email hoặc mật khẩu không chính xác",
                "Failed",
                HttpStatus.UNAUTHORIZED
            );
            throw new HttpException(response, HttpStatus.UNAUTHORIZED);
        }
        return user;
    }
}
