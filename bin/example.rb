#!/usr/bin/env ruby

require 'rubygems'
require 'optparse'
require '../lib/sshsocket'

options = {}

sock = SSHSocket::Socket.new()

