/*!
 * Copyright (c) 2023 Digital Credentials Consortium. All rights reserved.
 */
import crypto from 'crypto';
import Keyv from 'keyv';

const defaultExpiry = 1000 * 60 * 10; // store data expires after ten minutes

export class ChallengeManager {

  #expiresAfter;  // private field
  #keyv; // private field

  constructor({expiresAfter = defaultExpiry}:{expiresAfter: number}) {
    this.#expiresAfter = expiresAfter
    this.#keyv = new Keyv();
  }

  /**
 * @param data - Anything that the caller wants to store for later
 *  recovery, like say the data with which to construct a given credential,
 * for example, studentName, degreeType, etc.
 * @param expiresAfter - A specific millisecond value that
 *  overrides the default expiresAfter value.
 * @returns {string} The challenge, i.e, a UUID
 */
  public async createChallenge(data:any, expiresAfter:number = this.#expiresAfter): Promise<string> {
    const challenge = crypto.randomUUID() as string
    await this.#keyv.set(challenge, data, expiresAfter);
    return challenge
  }

/**
 * 
 * @param challenge 
 * @returns whatever was stored when the challenge was created
 */
  public async verifyChallenge(challenge:string) : Promise<any> {
    return await this.#keyv.get(challenge)
  }

}
