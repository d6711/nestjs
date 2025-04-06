import { Injectable } from '@nestjs/common';

@Injectable()
export class AuthService {
  attemp(): string {
    return 'test api tesdt';
  }
}
