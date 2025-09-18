declare module "passport-tiktok" {
  import { Strategy as PassportStrategy } from "passport-strategy";

  export interface TikTokProfile {
    id: string;
    username?: string;
    displayName?: string;
    photos?: { value: string }[];
    emails?: { value: string }[];
    _json: any;
  }

  export interface TikTokStrategyOptions {
    clientID: string;
    clientSecret: string;
    callbackURL: string;
    scope?: string[];
  }

  export class Strategy extends PassportStrategy {
    constructor(
      options: TikTokStrategyOptions,
      verify: (
        accessToken: string,
        refreshToken: string,
        profile: TikTokProfile,
        done: (error: any, user?: any) => void
      ) => void
    );
  }
}
