import { Injectable } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { User } from '../user/user.schema';
import { RefreshToken } from './refresh-token.schema';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<User>,
    @InjectModel(RefreshToken.name) private tokenModel: Model<RefreshToken>,
    private jwtService: JwtService,
  ) {}

  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, 10);
  }

  async validateUser(email: string, password: string): Promise<User | null> {
    const user = await this.userModel.findOne({ email }).exec();
    if (!user || !user.password) return null;
    const valid = await bcrypt.compare(password, user.password);
    return valid ? user : null;
  }

  async register(email: string, password: string): Promise<User> {
    const hashed = await this.hashPassword(password);
    const user = new this.userModel({ email, password: hashed });
    return user.save();
  }

  async generateAccessToken(userId: string): Promise<string> {
    return this.jwtService.sign({ sub: userId });
  }

  async generateRefreshToken(userId: string): Promise<string> {
    const token = this.jwtService.sign(
      { sub: userId },
      { expiresIn: '7d', secret: process.env.JWT_SECRET || 'secret' },
    );
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    await this.tokenModel.create({ userId, token, expiresAt });
    return token;
  }

  async refresh(token: string): Promise<string | null> {
    const stored = await this.tokenModel.findOne({ token }).exec();
    if (!stored) return null;
    if (stored.expiresAt < new Date()) return null;
    const payload = this.jwtService.verify(token, {
      secret: process.env.JWT_SECRET || 'secret',
    });
    return this.generateAccessToken(payload.sub);
  }
}
