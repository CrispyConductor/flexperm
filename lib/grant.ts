import * as objtools from 'objtools';
import { PermissionSet } from './permission-set.js';

/**
 * A class to encapsulate the permissions a user has on a specific match object. This is returned
 * by methods on PermissionSet instances, notably getTargetGrant, and is not intended to be constructed
 * as a standalone object.
 *
 * @class Grant
 * @constructor
 * @param {Object} grantObj - The grant object data.
 * @param {String} target - The target used to generate this grant.
 * @param {String} match - The match used to generate this grant.
 */
export class Grant {
	permissionSet: PermissionSet;
	grant: any;
	grantMask: objtools.ObjectMask;
	_target: string;
	_match: any;

	constructor(permissionSet: PermissionSet, grantObj: any, target: string, match: any) {
		this.permissionSet = permissionSet;
		this.grant = grantObj;
		this.grantMask = new objtools.ObjectMask(this.grant);
		this._target = target;
		this._match = match;
	}

	/**
	 * Retrieve the target used to generate this grant.
	 *
	 * @method getTarget
	 * @return {String}
	 */
	getTarget(): string {
		return this._target;
	}

	/**
	 * Retrieve the match used to generate this grant.
	 *
	 * @method getMatch
	 * @return {Object}
	 */
	getMatch(): any {
		return this._match;
	}

	/**
	 * Create a new grant, a subgrant of this one, from the given mask.
	 *
	 * @method createSubgrantFromMask
	 * @param {String} mask - A path in the current grant
	 * @return {Grant}
	 */
	createSubgrantFromMask(mask: string | any): Grant {
		if (typeof mask === 'string') {
			mask = this.getMask(mask);
		}
		return new Grant(this.permissionSet, mask, this._target, this._match);
	}

	/**
	 * Like createSubgrantFromMask(), but instead accepts an array of masks, and combines the
	 * resulting grants together for the return grant.
	 *
	 * @method createSubgrantFromMasks
	 * @param {Object[]} masks - An array of paths in the current grant
	 * @return {Grant}
	 */
	createSubgrantFromMasks(masks: any[]): Grant {
		const maskObjs: any[] = [];
		for (let i = 0; i < masks.length; i++) {
			if (typeof masks[i] === 'string') {
				maskObjs.push(this.getMask(masks[i]));
			} else {
				maskObjs.push(masks[i]);
			}
		}
		const mask = Grant.combineGrants(maskObjs);
		return new Grant(this.permissionSet, mask, this._target, this._match);
	}

	/**
	 * Returns the data associated with a Grant object.
	 *
	 * @method asObject
	 * @return {Object} - The grant data.
	 */
	asObject(): any {
		return this.grant;
	}

	/**
	 * See check(); this does the same thing, but instead of throwing an error on failure, returns false.
	 *
	 * @method has
	 * @param {String} k - The grant field to check for.
	 * @param {String} [prefix] - An optional prefix for the grant field.
	 * @return {Boolean} - Returns true on success, false on authorization failure.
	 */
	has(k: string | string[] | { [k: string]: boolean }, prefix?: string): boolean {
		if (!prefix) prefix = '';
		const grantMask = this.grantMask;
		if (this.grant === true) return true;
		if (typeof this.grant !== 'object') return false;

		function checkPath(path: string): boolean {
			return grantMask.checkPath(path);
		}

		if (typeof k === 'string') {
			return checkPath(prefix + k);
		} else if (Array.isArray(k)) {
			for (let i = 0; i < k.length; i++) {
				if (!checkPath(prefix + k[i])) return false;
			}
			return true;
		} else if (typeof k === 'object' && k) {
			for (let key in k) {
				if (k[key] && !checkPath(prefix + k[key])) return false;
			}
			return true;
		} else {
			return false;
		}
	}

	/**
	 * Check whether this grant contains a given field. This is the main function for checking authorization
	 * to procedures; it ensures that the PermissionSet that created this grant is authorized to the procedure
	 * represented by this functions, argument. An error is thrown on authorization failure.
	 *
	 * @method check
	 * @throws
	 * @param {String} k - The grant field to check for.
	 * @param {String} [prefix] - An optional prefix for the grant field.
	 * @return {Boolean} - Returns true on success.
	 */
	check(k: string | string[] | { [k:string]: boolean }, prefix?: string): boolean {
		if (!prefix) prefix = '';
		if (typeof k === 'string') {
			if (!this.has(k, prefix)) {
				if (this._target) {
					this.permissionSet.throwAccessError(
						`Access denied trying to ${prefix}${k} a target of type ${this._target}`,
						{ grantKey: prefix + k, target: this._target, match: this._match }
					);
					return false; //unreachable
				} else {
					this.permissionSet.throwAccessError(`Access denied trying to ${prefix}${k}`, {});
					return false; //unreachable
				}
			}
		} else if (Array.isArray(k)) {
			for (let i = 0; i < k.length; i++) {
				this.check(k[i], prefix);
			}
		} else if (typeof k === 'object' && k) {
			for (let key in k) {
				this.check(key, prefix);
			}
		} else {
			this.permissionSet.throwGeneralError(
				'Supplied invalid key to permission checking function',
				{ key: k }
			);
		}
		return true;
	}

	/**
	 * Checks an object against a mask that's a subcomponent of this grant.  If any field is in the object
	 * that is not matched by the grant, this throws.
	 * The mask argument can either be a mask object or a string path to a mask in this grant.
	 *
	 * @method checkMask
	 * @throws
	 * @param {String} mask - The name of the mask within the grant to use, e.g. 'updateMask'
	 * @param {Object} obj - The object to check against.
	 * @return {Boolean} - Returns true on success.
	 */
	checkMask(maskPath: string, obj: any): boolean {
		const mask: objtools.ObjectMask = new objtools.ObjectMask(this.getMask(maskPath));
		if (!obj || typeof obj !== 'object') {
			this.permissionSet.throwGeneralError('Tried to do permissions match against non-object', {});
		}

		const maskedOutFields: string[] = mask.getMaskedOutFields(obj);
		if (maskedOutFields.length > 0) {
			this.permissionSet.throwAccessError(
				`Access denied in ${maskPath || 'mask'} for objects of type ${this._target} ` +
				`to access field ${maskedOutFields[0]}`,
				{ grantKey: maskPath, target: this._target, match: this._match }
			);
			return false; //unreachable
		}
		return true;
	}

	/**
	 * Returns a sub-part of a grant.  May return boolean true (if all permissions granted) or
	 * boolean false (if no permission is granted) in the sub-part.
	 *
	 * @method get
	 * @param {String} k - string A dot-separated path in the grant data.
	 * @return {Mixed} - The contents of the grant portion, or true/false.
	 */
	get(k: string): any {
		return this.grantMask.getSubMask(k).toObject();
	}

	/**
	 * Returns the maximum of a numeric value in a grant.
	 *
	 * @method max
	 * @param {String} k - Path to a numeric grant within the grant data.
	 * @return {Number} - The max, or null if no such grant exists.
	 */
	max(k: string): number | null {
		let val = this.get(k);
		if (val === true) return Infinity;
		if (val && val.max === true) return Infinity;
		if (!val || typeof val !== 'object' || !val.grantNumber || typeof val.max !== 'number') return null;
		return val.max;
	}

	/**
	 * Returns the minimum of a numeric value in a grant.
	 *
	 * @method min
	 * @param {String} k - Path to a numeric grant within the grant data.
	 * @return {Number} - The min, or null if no such grant exists.
	 */
	min(k: string): number | null {
		let val = this.get(k);
		if (val === true) return -Infinity;
		if (val && val.min === true) return -Infinity;
		if (!val || typeof val !== 'object' || !val.grantNumber || typeof val.min !== 'number') return null;
		return val.min;
	}

	/**
	 * Check a path and number against this grant. This only makes sense if the path points to a numeric grant.
	 *
	 * @method checkNumber
	 * @throws
	 * @param {String} k - Path to a numeric grant within the grant data.
	 * @param {Number} num - The input number to be authorized.
	 * @return {Boolean} - Returns true on success.
	 */
	checkNumber(k: string, num: number): boolean {
		let min = this.min(k);
		let max = this.max(k);
		if (typeof min !== 'number' || typeof max !== 'number') {
			this.permissionSet.throwAccessError(
				'Attempted numeric permission check against non-numeric or missing grant',
				{ grantKey: k }
			);
			return false; //unreachable
		}
		if (typeof num !== 'number') {
			this.permissionSet.throwAccessError(
				'Attempted numeric permission check with non-numeric input',
				{ grantKey: k, value: num }
			);
			return false; //unreachable
		}
		if (num < min) {
			this.permissionSet.throwAccessError(
				'Attempted operation numeric value is smaller than grant minimum',
				{ grantKey: k, value: num, minimum: min, target: this._target, match: this._match }
			);
			return false; //unreachable
		}
		if (num > max) {
			this.permissionSet.throwAccessError(
				'Attempted operation numeric value is greater than grant maximum',
				{ grantKey: k, value: num, maximum: max, target: this._target, match: this._match }
			);
			return false; //unreachable
		}
		return true;
	}

	/**
	 * Returns a mask/whitelist at the given path in the grant.
	 *
	 * @method getMask
	 * @protected
	 * @param {String} k - A path in the grant.
	 * @return {Mixed} - The mask at that path in the grant (can be boolean true or false as well)
	 */
	getMask(k: string): any {
		let mask = this.get(k);
		if (mask !== true && typeof mask !== 'object') return false;
		return mask;
	}

	/**
	 * Combines multiple grant objects together. The result will have authorization to all of the abilities of
	 * each original grant.
	 *
	 * @method combineGrants
	 * @param {Mixed} grant1...n - Grant object contents to combine (not Grant objects, the actual data)
	 * @return {Object} The combined grant object.
	 */
	static combineGrants(...args: any[]): any {
		// This code is copied and modified from objtools addMasks() function
		let resultMask: boolean = false;

		// Adds a single mask (fromMask) into the resultMask mask in-place.  toMask should be an object.
		// If the resulting mask is a boolean true, this function returns true.  Otherwise, it returns toMask.
		function addMask(resultMask, newMask) {
			let key;

			if (resultMask === true) return true;
			if (newMask === true) {
				resultMask = true;
				return resultMask;
			}
			if (objtools.isScalar(newMask)) return resultMask;
			if (objtools.isScalar(resultMask)) {
				resultMask = objtools.deepCopy(newMask);
				return resultMask;
			}

			if (Array.isArray(resultMask)) {
				resultMask = { _: resultMask[0] || false };
			}
			if (Array.isArray(newMask)) {
				newMask = { _: newMask[0] || false };
			}

			// Handle the case of grant numbers
			if (resultMask.grantNumber && newMask.grantNumber) {
				resultMask.min = Math.min(resultMask.min, newMask.min);
				resultMask.max = Math.max(resultMask.max, newMask.max);
				return resultMask;
			} else if (resultMask.grantNumber || newMask.grantNumber) {
				return false;	// Mismatched types ... can't really handle it better
			}

			// If there are keys that exist in result but not in the newMask,
			// and the result mask has a _ key (wildcard), combine
			// the wildcard mask with the new mask, because in the existing result mask,
			// that key has the wildcard permissions
			if (newMask._ !== undefined) {
				for (key in resultMask) {
					if (key === '_') continue;
					if (newMask[key] === undefined) {
						resultMask[key] = addMask(resultMask[key], newMask._);
					}
				}
			}

			// same here ... also, copy over or merge fields
			for (key in newMask) {
				if (key === '_') continue;
				if (resultMask[key] !== undefined) {
					resultMask[key] = addMask(resultMask[key], newMask[key]);
				} else if (resultMask._ !== undefined) {
					resultMask[key] = addMask(objtools.deepCopy(newMask[key]), resultMask._);
				} else {
					resultMask[key] = objtools.deepCopy(newMask[key]);
				}
			}
			// fill in the _ key that we skipped earlier
			if (newMask._ !== undefined) {
				if (resultMask._ !== undefined) resultMask._ = addMask(resultMask._, newMask._);
				else resultMask._ = objtools.deepCopy(newMask._);
			}

			return resultMask || false;
		}

		for (let argIdx = 0; argIdx < args.length; argIdx++) {
			resultMask = addMask(resultMask, args[argIdx]);
			if (resultMask === true) return true;
		}
		return resultMask || false;
	}

	static grantNumbersToObjects(grantObj: any): any {
		if (grantObj && typeof grantObj === 'object' && !grantObj.grantNumber) {
			let newObj = {};
			for (let k in grantObj) {
				newObj[k] = Grant.grantNumbersToObjects(grantObj[k]);
			}
			return newObj;
		} else if (typeof grantObj === 'number') {
			return {
				grantNumber: true,
				min: grantObj,
				max: grantObj
			};
		} else {
			return grantObj;
		}
	}
}

