let expect = require('chai').expect;
var PermissionSet = require('../lib/index');



describe('Permissions', function() {

	it('can construct a permission set', function() {
		expect(function() {
			return new PermissionSet([]);
		}).to.not.throw(Error);
	});

});
