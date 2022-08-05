import {
  Body,
  Controller,
  ForbiddenException,
  HttpCode,
  HttpStatus,
  Post,
  UseGuards,
} from '@nestjs/common';

import { AuthService } from './auth.service';
import { GetCurrentUser, GetCurrentUserId, Public } from './decorators';
import { AuthDto } from './dto';
import { RefreshTokenGuard } from './guards';
import { Tokens } from './types';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) { }

  @Public()
  @Post('local/register')
  registerLocal(@Body() dto: AuthDto): Promise<Tokens> {
    return this.authService.registerLocal(dto);
  }

  @Public()
  @Post('local/login')
  @HttpCode(HttpStatus.OK)
  async loginLocal(@Body() dto: AuthDto): Promise<Tokens> {
    const tokens = await this.authService.loginLocal(dto);
    if (!tokens) {
      throw new ForbiddenException('Wrong email or password');
    }
    return tokens;
  }

  @Post('logout')
  @HttpCode(HttpStatus.NO_CONTENT)
  logout(@GetCurrentUserId() userId: number) {
    return this.authService.logout(userId);
  }

  @Public()
  @UseGuards(RefreshTokenGuard)
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(
    @GetCurrentUserId() userId: number,
    @GetCurrentUser('refreshToken') refreshToken: string
  ) {
    const tokens = await this.authService.refresh(userId, refreshToken);
    if (!tokens) {
      throw new ForbiddenException('Access denied');
    }
    return tokens;
  }
}
