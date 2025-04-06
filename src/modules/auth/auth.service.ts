import { Injectable } from "@nestjs/common";
import { AuthRequest } from "./auth.request.dto";
import { PrismaService } from "../prisma/prisma.service";
import * as bcrypt from "bcrypt";
import { UserWithoutPassword } from "../users/user.interface";

@Injectable()
export class AuthService {
    constructor(private readonly prismaService: PrismaService) {}
    authenticate(request: AuthRequest): string {
        console.log(request);
        return "Send auth request";
    }
    async validateUser(
        email: string,
        password: string
    ): Promise<UserWithoutPassword | null> {
        const user = await this.prismaService.user.findUnique({
            where: { email }
        });
        if (!user) {
            return null;
        }
        const isPassworValid = await bcrypt.compare(password, user.password);
        if (!isPassworValid) {
            return null;
        }
        const { password: _, ...result } = user;
        return result;
    }
}
