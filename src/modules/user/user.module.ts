import { Module } from '@nestjs/common';
import { UserRepository } from './user.repository';

@Module({
    imports: [],
    providers: [UserRepository]
})
export class UserModule { }
