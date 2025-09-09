import {
  PublicKeyCredentialCreationOptionsJSON,
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
  PublicKeyCredentialRequestOptionsJSON,
} from '@simplewebauthn/types';
import {LoginResponse, UserResponse} from '@sharedTypes/MessageTypes';
import {NextFunction, Request, Response} from 'express';
import CustomError from '../../classes/CustomError';
import {User} from '@sharedTypes/DBTypes';
import fetchData from '../../utils/fetchData';
import {
  generateAuthenticationOptions,
  GenerateAuthenticationOptionsOpts,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  VerifyAuthenticationResponseOpts,
  verifyRegistrationResponse,
  VerifyRegistrationResponseOpts,
} from '@simplewebauthn/server';
import {
  Challenge,
  PasskeyUserGet,
  PasskeyUserPost,
} from '../../types/PasskeyTypes';
import challengeModel from '../models/challengeModel';
import authenticatorDeviceModel from '../models/authenticatorDeviceModel';
import {Types} from 'mongoose';
import passkeyUserModel from '../models/passkeyUserModel';
import jwt from 'jsonwebtoken';

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
    const {credentialPublicKey, credentialID, counter} = registrationInfo;
    const existingDevice = await authenticatorDeviceModel.findOne({
      credentialID,
    });
    if (existingDevice) {
      next(new CustomError('Decive already registered', 400));
      return;
    }
    // Save new authenticator to AuthenticatorDevice collection
    const newDevice = new authenticatorDeviceModel({
      email: req.body.email,
      credentialPublicKey: Buffer.from(credentialPublicKey),
      credentialID,
      counter,
      transports: req.body.registrationOptions.response.transports,
    });

    const newDeviceResult = await newDevice.save();

    // Update user devices array in DB (eri esim) // findOneAndUpdate
    const user = await passkeyUserModel.findOne({email: req.body.email});
    if (!user) {
      next(new CustomError('User not found', 404));
      return;
    }
    // lisää taulukkoon
    user.devices.push(newDeviceResult._id as Types.ObjectId);
    await user.save();

    // Clear challenge from DB after successful registration
    // - jos ei poista, käyttäjä ei pysty lisäämään uusia laitteita
    await challengeModel.findByIdAndDelete({email: req.body.email});

    // Retrieve and send user details from AUTH API
    const userResponse = await fetchData<UserResponse>(
      AUTH_URL + '/api/v1/users/' + user.userId,
    );
    res.json(userResponse);
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// Generate authentication options handler
const authenticationOptions = async (
  req: Request<{}, {}, {email: string}>,
  res: Response<PublicKeyCredentialRequestOptionsJSON>,
  next: NextFunction,
) => {
  try {
    // Retrieve user and associated devices from DB
    const user = (await passkeyUserModel
      .findOne({email: req.body.email})
      .populate('devices')) as unknown as PasskeyUserGet;

    if (!user) {
      next(new CustomError('User not found', 404));
      return;
    }

    // Generate authentication options
    const aopts: GenerateAuthenticationOptionsOpts = {
      timeout: 60000,
      rpID: RP_ID,
      allowCredentials: user.devices.map((device) => {
        return {
          id: device.credentialID,
          type: 'public-key',
          transports: device.transports,
        };
      }),
      userVerification: 'preferred',
    };

    const authOptions = await generateAuthenticationOptions(aopts);

    // Save challenge to DB
    await challengeModel.create({
      email: req.body.email,
      challenge: authOptions.challenge,
    });

    // Send options in response
    res.send(authOptions);
  } catch (error) {
    next(new CustomError((error as Error).message, 500));
  }
};

// Authentication verification and login handler
const verifyAuthentication = async (
  req: Request<
    {},
    {},
    {email: string; authenticationResponse: AuthenticationResponseJSON}
  >,
  res: Response<LoginResponse>,
  next: NextFunction,
) => {
  try {
    // Retrieve expected challenge from DB
    const eChallenge = await challengeModel.findOne({
      email: req.body.email,
    });
    if (!eChallenge) {
      next(new CustomError('Challenge not found', 404));
      return;
    }
    // Verify authentication response
    const user = (await passkeyUserModel
      .findOne({email: req.body.email})
      .populate('devices')) as unknown as PasskeyUserGet;

    if (!user) {
      next(new CustomError('User not found', 404));
      return;
    }

    const verifyOptions: VerifyAuthenticationResponseOpts = {
      expectedRPID: RP_ID,
      response: req.body.authenticationResponse,
      expectedChallenge: eChallenge.challenge,
      expectedOrigin:
        NODE_ENV === 'development' ? `http://${RP_ID}:5137` : `http://${RP_ID}`,
      authenticator: {
        credentialPublicKey: Buffer.from(user.devices[0].credentialPublicKey),
        credentialID: user.devices[0].credentialID,
        counter: user.devices[0].counter,
      },
      requireUserVerification: false,
    };

    const verification = await verifyAuthenticationResponse(verifyOptions);
    const {verified, authenticationInfo} = verification;

    // Update authenticator's counter
    if (!verified) {
      await authenticatorDeviceModel.findByIdAndUpdate(user.devices[0]._id, {
        counter: authenticationInfo.newCounter,
      });
    }

    // Clear challenge from DB after successful authentication
    await challengeModel.findOneAndDelete({email: req.body.email});

    // Generate and send JWT
    const userResponse = await fetchData<UserResponse>(
      AUTH_URL + '/api/v1/users/' + user.userId,
    );
    if (!userResponse) {
      next(new CustomError('User not found', 404));
      return;
    }
    const token = jwt.sign(
      {
        user_id: userResponse.user.user_id,
        level_name: userResponse.user.level_name,
      },
      JWT_SECRET,
    );
    const message: LoginResponse = {
      message: 'Login successful',
      user: userResponse.user,
      token: token,
    };
    res.json(message);
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
