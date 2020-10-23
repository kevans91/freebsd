#!/usr/libexec/flua

local be = require('be')

for be in be.list({"used", "active"}) do
	print(be['name'])
	print(be["used"])
	print(be["active"])
end
