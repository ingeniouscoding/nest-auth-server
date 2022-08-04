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

    const tokens = await this.getTokens(newUser.id, newUser.email);
    await this.updateHash(newUser.id, tokens.refresh_token);
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

    const tokens = await this.getTokens(user.id, user.email);
    await this.updateHash(user.id, tokens.refresh_token);
    return tokens;
  }

  logout() { }

  refresh() { }

  private async updateHash(userId: number, rt: string): Promise<void> {
    const hash = await this.hashString(rt);
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

  private async getTokens(userId: number, email: string): Promise<Tokens> {
    const [at, rt] = await Promise.all([
      this.jwtService.signAsync({
        sub: userId,
        email,
      }, {
        secret: 'at-secret',
        expiresIn: 60 * 15,
      }),
      this.jwtService.signAsync({
        sub: userId,
        email,
      }, {
        secret: 'rt-secret',
        expiresIn: 60 * 60 * 24 * 7,
      })
    ]);

    return {
      access_token: at,
      refresh_token: rt,
    };
  }
}
