import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';

import { PrismaService } from 'src/prisma/prisma.service';

import { AuthDto } from './dto';
import { Tokens } from './types';

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService
  ) { }

  async registerLocal(dto: AuthDto): Promise<Tokens> {
    const hash = await this.hashString(dto.password);
    const newUser = await this.prisma.user
      .create({
        data: {
          email: dto.email,
          hash,
        },
      });

    const tokens = await this.generateTokens(newUser.id, newUser.email);
    await this.updateRefreshToken(newUser.id, tokens.refresh_token);
    return tokens;
  }

  async loginLocal(dto: AuthDto): Promise<Tokens | null> {
    const user = await this.prisma.user
      .findUnique({
        where: {
          email: dto.email,
        },
      });

    if (!user) {
      return null;
    }

    const isPasswordMatch = await bcrypt.compare(dto.password, user.hash);
    if (!isPasswordMatch) {
      return null;
    }

    const tokens = await this.generateTokens(user.id, user.email);
    await this.updateRefreshToken(user.id, tokens.refresh_token);
    return tokens;
  }

  async logout(userId: number) {
    await this.prisma.user
      .updateMany({
        where: {
          id: userId,
          hashedRt: {
            not: null,
          },
        },
        data: {
          hashedRt: null,
        },
      });
  }

  async refresh(userId: number, refreshToken: string) {
    const user = await this.prisma.user
      .findUnique({
        where: {
          id: userId,
        },
      });

    if (!user || user.hashedRt === null) {
      return null;
    }
    const tokenSignature = refreshToken.split('.')[2];
    const isTokenMatch = await bcrypt.compare(tokenSignature, user.hashedRt);
    if (!isTokenMatch) {
      return null;
    }

    const tokens = await this.generateTokens(user.id, user.email);
    await this.updateRefreshToken(user.id, tokens.refresh_token);
    return tokens;
  }

  private async updateRefreshToken(userId: number, rt: string): Promise<void> {
    const tokenSignature = rt.split('.')[2];
    const hash = await bcrypt.hash(tokenSignature, 10);
    await this.prisma.user
      .update({
        where: {
          id: userId,
        },
        data: {
          hashedRt: hash,
        },
      });
  }

  private hashString(data: string): Promise<string> {
    return bcrypt.hash(data, 10);
  }

  private async generateTokens(userId: number, email: string): Promise<Tokens> {
    const [at, rt] = await Promise.all([
      this.jwtService.signAsync({
        sub: userId,
        email,
      }, {
        secret: 'at-secret',
        expiresIn: '15m',
      }),
      this.jwtService.signAsync({
        sub: userId,
        email,
      }, {
        secret: 'rt-secret',
        expiresIn: '7d',
      })
    ]);

    return {
      access_token: at,
      refresh_token: rt,
    };
  }
}
