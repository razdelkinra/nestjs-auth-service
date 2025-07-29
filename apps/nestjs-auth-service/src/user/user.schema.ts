import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';

@Schema({ timestamps: true })
export class User extends Document {
  @Prop({ required: true, unique: true })
  email: string;

  @Prop()
  password?: string;

  @Prop()
  googleId?: string;
}

export const UserSchema = SchemaFactory.createForClass(User);
