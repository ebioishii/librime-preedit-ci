-- Synthetic CI fixture only; no user schema or third-party Lua is included.
return function(input, segment, env)
  -- Runs during Query(), before the engine finishes assembling the menu.
  -- Inspect only its presence: do not prepare or consume partial candidates.
  assert(segment.menu ~= nil, "patched Query() must receive a menu")
  if input == "lua" then
    yield(Candidate("lua_smoke", segment.start, segment._end,
                    "LUA_OK", "isolated CI"))
  end
  -- The C++ test checks this after draining the coroutine, so a swallowed
  -- Lua error or an uncalled translator cannot silently pass the test.
  env.engine.context:set_property("lua_smoke_done", input)
end
