"use strict";

var t = require('chai').assert;
var express = require('express');
var request = require('supertest');
var veritoken = require('../');


describe('veritoken', function () {

    it('should verify token', function (done) {
        var user = {name: 'ty', token: '1234567890'};
        var app = express();
        app.use(veritoken({
            headers: ['authorization'],
            property: 'user'
        }, function (token, cb) {
            if (token === user.token) {
                cb(null, user);
            } else {
                cb();
            }
        }));
        app.use(function (req, res, next) {
            t.equal(req.user, user);
            res.status(200).end();
        });

        request(app)
            .get('/')
            .set('authorization', user.token)
            .expect(200)
            .end(function (err, res) {
                t.notOk(res.body.error);
                done();
            });
    });
});