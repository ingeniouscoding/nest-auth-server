import { Body, Controller, ForbiddenException, Post } from '@nestjs/common';

import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { Tokens } from './types';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) { }

  @Post('local/register')
  registerLocal(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.registerLocal(dto);
  }

  @Post('local/login')
  async loginLocal(@Body() dto: AuthDto): Promise<Tokens> {
    const tokens = await this.authService.loginLocal(dto);
    if (!tokens) {
      throw new ForbiddenException('Wrong email or password');
    }
    return tokens;
  }

  @Post('logout')
  logout() {
    return this.authService.logout();
  }

  @Post('refresh')
  refresh() {
    return this.authService.refresh();
  }
}
