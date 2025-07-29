import { Body, Controller, Post, Get, Req, Res } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto } from './dto/signup.dto';
import { LoginDto } from './dto/login.dto';
import { Request, Response } from 'express';
import { Auth, type AuthConfig } from '@auth/core';
import GoogleProvider from '@auth/core/providers/google';
import { MongoDBAdapter } from '@auth/mongodb-adapter';
import { MongoClient } from 'mongodb';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  async signup(@Body() dto: SignupDto) {
    const user = await this.authService.register(dto.email, dto.password);
    const accessToken = await this.authService.generateAccessToken(user.id);
    const refreshToken = await this.authService.generateRefreshToken(user.id);
    return { accessToken, refreshToken };
  }

  @Post('login')
  async login(@Body() dto: LoginDto) {
    const user = await this.authService.validateUser(dto.email, dto.password);
    if (!user) return { error: 'invalid credentials' };
    const accessToken = await this.authService.generateAccessToken(user.id);
    const refreshToken = await this.authService.generateRefreshToken(user.id);
    return { accessToken, refreshToken };
  }

  @Post('refresh')
  async refresh(@Body('refreshToken') token: string) {
    const accessToken = await this.authService.refresh(token);
    return { accessToken };
  }

  @Get('google')
  async google(@Req() req: Request, @Res() res: Response) {
    const client = new MongoClient(process.env.MONGO_URI || '');
    await client.connect();
    const authOptions: AuthConfig = {
      providers: [
        GoogleProvider({
          clientId: process.env.GOOGLE_CLIENT_ID || '',
          clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
        }),
      ],
      session: { strategy: 'jwt' },
      adapter: MongoDBAdapter(client),
      secret: process.env.JWT_SECRET,
    };
    const url = `${req.protocol}://${req.get('host')}${req.originalUrl}`;
    const authReq = new globalThis.Request(url, {
      headers: req.headers as any,
      method: req.method,
    });
    const response = await Auth(authReq, authOptions);
    res.status(response.status);
    response.headers.forEach((value, key) => res.setHeader(key, value));
    const body = await response.text();
    res.send(body);
  }
}
