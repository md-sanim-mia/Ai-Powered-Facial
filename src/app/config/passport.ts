import passport, { use } from "passport";
import { Strategy as GoogleStrategy, Profile } from "passport-google-oauth20";
import { Strategy as FacebookStrategy, Profile as FacebookProfile } from "passport-facebook";
import { Strategy as OAuth2Strategy } from "passport-oauth2";
import prisma from "../utils/prisma";
import config from ".";
import { jwtHelpers } from "../helpers/jwtHelpers";
import axios from "axios";
import { randomBytes, createHash } from "crypto";


function base64URLEncode(str: Buffer) {
  return str.toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function generateCodeVerifier() {
  return base64URLEncode(randomBytes(32));
}

export function generateCodeChallenge(verifier: string) {
  const hash = createHash("sha256").update(verifier).digest();
  return base64URLEncode(hash);
}

passport.use(
  new GoogleStrategy(
    {
      clientID: config.googleAuth.clientID!,
      clientSecret: config.googleAuth.clientSecret!,
      callbackURL: config.googleAuth.callbackURL!,
    },
    async (accessToken: string, refreshToken: string, profile: Profile, done) => {
     
      try {
        // email দিয়ে check
        let user = await prisma.user.findUnique({
          where: { email: profile.emails![0].value },
        });


        if (!user) {
          user = await prisma.user.create({
            data: {
              fullName: profile.displayName,
              email: profile.emails![0].value,
              password: Math.random().toString(36).slice(-8), // dummy password
              profilePic: profile.photos?.[0].value || "",
              isVerified: true,
            },
          });
        }

        // JWT generate
        const jwtPayload = {
          id: user.id,
          fullName: user.fullName,
          email: user.email,
          role: user.role,
          profilePic: user.profilePic,
          isVerified: user.isVerified,
        };

        const accessToken = jwtHelpers.createToken(
          jwtPayload,
          config.jwt.access.secret!,
          config.jwt.access.expiresIn!
        );

        done(null, { accessToken });
      } catch (err) {
        done(err, undefined);
      }
    }
  )
);
passport.use(
  new FacebookStrategy(
    {
      clientID: config.facebookAuth.clientID!,
      clientSecret: config.facebookAuth.clientSecret!,
      callbackURL: config.facebookAuth.callbackURL!,
      profileFields: ['id', 'displayName', 'photos', 'email'] // Request email permission
    },
    async (accessToken: string, refreshToken: string, profile: FacebookProfile, done) => {
   
      try {
        // Facebook sometimes doesn't provide email
        const email = profile.emails?.[0]?.value || `${profile.id}@facebook.com`;
        
        let user = await prisma.user.findUnique({
          where: { email: email },
        });

        if (!user) {
          user = await prisma.user.create({
            data: {
              fullName: profile.displayName || profile.name?.givenName + " " + profile.name?.familyName || "Facebook User",
              email: email,
              password: Math.random().toString(36).slice(-8),
              profilePic: profile.photos?.[0]?.value || "",
              isVerified: true,
            },
          });
        }
        console.log(user)

        const jwtPayload = {
          id: user.id,
          fullName: user.fullName,
          email: user.email,
          role: user.role,
          profilePic: user.profilePic,
          isVerified: user.isVerified,
        };

        const token = jwtHelpers.createToken(
          jwtPayload,
          config.jwt.access.secret!,
          config.jwt.access.expiresIn!
        );

        done(null, { accessToken: token });
      } catch (err) {
        done(err, undefined);
      }
    }
  )
);

let codeVerifierStore: Record<string, string> = {}; // session-store এর মতো কাজ করবে

passport.use(
  "tiktok",
  new OAuth2Strategy(
    {
      authorizationURL: "https://www.tiktok.com/v2/auth/authorize/",
      tokenURL: "https://open.tiktokapis.com/v2/oauth/token/",
      clientID: config.tiktokAuth.clientID!,
      clientSecret: config.tiktokAuth.clientSecret!,
      callbackURL: config.tiktokAuth.callbackURL!,
      scope: "user.info.basic",
      passReqToCallback: true,
    },
    async (req: any, accessToken: string, refreshToken: string, params: any, profile: any, done: any) => {
      try {
        // TikTok থেকে user info আনো
        const userInfo = await axios.post(
          "https://open.tiktokapis.com/v2/user/info/",
          {},
          {
            headers: {
              Authorization: `Bearer ${accessToken}`,
              "Content-Type": "application/json",
            },
            params: {
              fields: "open_id,union_id,avatar_url,display_name",
            },
          }
        );

        const tiktokUser = userInfo.data.data.user;
        const email = `${tiktokUser.open_id}@tiktok.local`;

        let user = await prisma.user.findUnique({ where: { email } });
        if (!user) {
          user = await prisma.user.create({
            data: {
              fullName: tiktokUser.display_name || "TikTok User",
              email,
              password: Math.random().toString(36).slice(-8),
              profilePic: tiktokUser.avatar_url || "",
              isVerified: true,
            },
          });
        }

        const jwtPayload = {
          id: user.id,
          fullName: user.fullName,
          email: user.email,
          role: user.role,
          profilePic: user.profilePic,
          isVerified: user.isVerified,
        };

        const token = jwtHelpers.createToken(
          jwtPayload,
          config.jwt.access.secret!,
          config.jwt.access.expiresIn!
        );

        return done(null, { accessToken: token });
      } catch (err: any) {
        console.error("TikTok OAuth2 Error:", err.response?.data || err);
        return done(err, null);
      }
    }
  )
);

// Override authorizationParams → PKCE add করা
OAuth2Strategy.prototype.authorizationParams = function (options: any) {
  const verifier = generateCodeVerifier();
  const challenge = generateCodeChallenge(verifier);

  // user session-এ verifier রাখো
  codeVerifierStore[options.state] = verifier;

  return {
    code_challenge: challenge,
    code_challenge_method: "S256",
  };
};

// Override tokenParams → verifier পাঠাও
OAuth2Strategy.prototype.tokenParams = function (options: any) {
  return {
    code_verifier: codeVerifierStore[options.state],
  };
};



export default passport;
