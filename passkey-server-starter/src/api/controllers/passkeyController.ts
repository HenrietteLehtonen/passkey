import {UserResponse} from '@sharedTypes/MessageTypes';
import e, {NextFunction, Request, Response} from 'express';
import CustomError from '../../classes/CustomError';
import {User} from '@sharedTypes/DBTypes';
import fetchData from '../../utils/fetchData';
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  VerifyRegistrationResponseOpts,
} from '@simplewebauthn/server';
import {Challenge, PasskeyUserPost} from '../../types/PasskeyTypes';
import challengeModel from '../models/challengeModel';
import passkeyUserModel from '../models/passkeyUserModel';
import {RegistrationResponseJSON} from '@simplewebauthn/server/script/deps';

// check environment variables
if (
  !process.env.NODE_ENV ||
  !process.env.RP_ID ||
  !process.env.AUTH_URL ||
  !process.env.JWT_SECRET ||
  !process.env.RP_NAME
) {
  throw new Error('Environment variables not set');
}

// Destructure environment variables =  process.env.AUTH_URL -> AUTH_URL
const {NODE_ENV, RP_ID, AUTH_URL, JWT_SECRET, RP_NAME} = process.env;
console.log({NODE_ENV, RP_ID, AUTH_URL, JWT_SECRET, RP_NAME});

// Registration handler
const setupPasskey = async (
  req: Request<{}, {}, User>,
  res: Response<{
    email: string;
    options: PublicKeyCredentialCreationOptionsJSON;
  }>,
  next: NextFunction,
) => {
  try {
    // Register user with AUTH API
    const options: RequestInit = {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(req.body),
    };
    const userResponse = await fetchData<UserResponse>(
      AUTH_URL + '/api/v1/users',
      options,
    );
    if (!userResponse) {
      next(new CustomError('User not created', 400));
      return;
    }
    console.log('user', userResponse);

    // Generate registration options
    const regOptions = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userName: userResponse.user.username,
      attestationType: 'none',
      timeout: 60000,
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
      supportedAlgorithmIDs: [-7, -257],
    });

    // Save challenge to DB
    const challenge: Challenge = {
      challenge: regOptions.challenge,
      email: userResponse.user.email,
    };
    await challengeModel.create(challenge); // save to db

    //  Add user to PasskeyUser collection
    const passkeyUser: PasskeyUserPost = {
      email: userResponse.user.email,
      userId: userResponse.user.user_id,
      devices: [], // ei tiedetä laitteita -> tyhjä taulukko
    };
    await passkeyUserModel.create(passkeyUser);

    //  Send response with email and options
    res.json({
      email: userResponse.user.email,
      options: regOptions,
    });
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// Registration verification handler
const verifyPasskey = async (
  req: Request<
    {},
    {},
    {email: string; registrationOptions: RegistrationResponseJSON}
  >,
  res: Response<UserResponse>,
  next: NextFunction,
) => {
  try {
    // Retrieve expected challenge from DB
    const expectedChallenge = await challengeModel.findOne({
      email: req.body.email,
    });
    if (!expectedChallenge) {
      next(new CustomError('Challenge not found', 404));
      return;
    }
    console.log('expectedChallenge', expectedChallenge);

    // Verify registration response
    const opts: VerifyRegistrationResponseOpts = {
      response: req.body.registrationOptions,
      expectedChallenge: expectedChallenge.challenge,
      expectedOrigin: `http://${RP_ID}:5173/`, //'http://localhost:5173/'
      expectedRPID: RP_ID!,
    };
    const verification = await verifyRegistrationResponse(opts);
    const {verified, registrationInfo} = verification;
    // console.log('verification', verification);
    if (!verified || !registrationInfo) {
      next(new CustomError('Verification failed', 403));
      return;
    }
    // Check if device is already registered

    // TODO: Save new authenticator to AuthenticatorDevice collection
    // TODO: Update user devices array in DB
    // TODO: Clear challenge from DB after successful registration
    // TODO: Retrieve and send user details from AUTH API
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// Generate authentication options handler
const authenticationOptions = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  try {
    // TODO: Retrieve user and associated devices from DB
    // TODO: Generate authentication options
    // TODO: Save challenge to DB
    // TODO: Send options in response
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// Authentication verification and login handler
const verifyAuthentication = async (
  req: Request,
  res: Response,
  next: NextFunction,
) => {
  try {
    // TODO: Retrieve expected challenge from DB
    // TODO: Verify authentication response
    // TODO: Update authenticator's counter
    // TODO: Clear challenge from DB after successful authentication
    // TODO: Generate and send JWT token
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

export {
  setupPasskey,
  verifyPasskey,
  authenticationOptions,
  verifyAuthentication,
};
