import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as bcrypt from 'bcrypt'
import { JwtService } from '@nestjs/jwt';
import { Tokens } from './types';

@Injectable()
export class AuthService {
    constructor(
        private prisma: PrismaService,
        private jwtService: JwtService) { }

    hashData(data: string) {
        return bcrypt.hash(data, 10);
    }

    async getTokens(userId: number, email: string): Promise<Tokens> {
        const [accessToken, refreshToken] = await Promise.all([
            this.jwtService.signAsync({
                sub: userId,
                email
            }, {
                expiresIn: 60 * 15, //15 minutes
                secret: 'access-secret-test'

            }),
            this.jwtService.signAsync({
                sub: userId,
                email
            }, {
                expiresIn: 60 * 60 * 24 * 7, //1 week
                secret: 'refresh-secret-test'
            }),
        ]);

        return {
            access_token: accessToken,
            refresh_token: refreshToken,
        }

    }

    async signupLocal(dto: AuthDto): Promise<Tokens> {
        const hash = await this.hashData(dto.password);
        const newUser = await this.prisma.user.create({
            data: {
                email: dto.email,
                hash
            }
        })
        const tokens = await this.getTokens(newUser.id, newUser.email)
        await this.updateRefreshHash(newUser.id, tokens.refresh_token)
        return tokens
    }



    async signinLocal(dto: AuthDto): Promise<Tokens> {
        const user = await this.prisma.user.findUnique({
            where: {
                email: dto.email
            }
        })

        if (!user) throw new ForbiddenException("Access Denied");

        const passwordMatches = await bcrypt.compare(dto.password, user.hash)

        if (!passwordMatches) throw new ForbiddenException("Access Denied");


        const tokens = await this.getTokens(user.id, user.email)
        await this.updateRefreshHash(user.id, tokens.refresh_token)
        return tokens

    }

    async logout(userId: number) {
        console.log({ userId })
        return await this.prisma.user.updateMany({
            where: {
                id: userId,
                hashedRtoken: {
                    not: null
                }
            },
            data: {
                hashedRtoken: null
            }
        })
    }

    async refreshToken(userId: number, refreshToken: string) {
        const user = await this.prisma.user.findUnique({
            where: ({
                id: userId
            })
        })

        if (!user) throw new ForbiddenException("Access Denied");
        if (!user.hashedRtoken) throw new ForbiddenException("Access Denied");

        const rtMatches = bcrypt.compare(refreshToken, user.hashedRtoken)
        if (!rtMatches) throw new ForbiddenException("Access Denied");
        console.log({ rtMatches })

        const tokens = await this.getTokens(user.id, user.email)
        await this.updateRefreshHash(user.id, tokens.refresh_token)
        return tokens;
    }


    async updateRefreshHash(userId: number, refreshToken: string) {
        const hash = await this.hashData(refreshToken);
        await this.prisma.user.update({
            where: {
                id: userId
            },
            data: {
                hashedRtoken: hash
            }
        })
    }
}
