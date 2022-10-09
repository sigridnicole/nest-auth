import { PassportStrategy } from "@nestjs/passport";
import { ExtractJwt, Strategy } from "passport-jwt";
import { Injectable } from '@nestjs/common';

type JWTPayload = {
    sub: string;
    email: string;
}

@Injectable()
export class AccessStrategy extends PassportStrategy(Strategy, 'jwt') {
    constructor() {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: 'access-secret-test',
        })
    }

    /**
     * @todo: Add validation.
    */
    validate(payload: JWTPayload) {
        return payload
    }
}