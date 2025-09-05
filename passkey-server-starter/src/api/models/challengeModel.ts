import {model, Schema} from 'mongoose';
import {Challenge} from '../../types/PasskeyTypes';

const challengeSchema = new Schema<Challenge>({
  // add challenge (String, required)
  // add email (String, required, unique)
  challenge: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
});

export default model<Challenge>('Challenge', challengeSchema);
