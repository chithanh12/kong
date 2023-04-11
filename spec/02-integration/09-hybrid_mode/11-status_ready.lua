-- 09-hybrid_mode/11-status_ready.lua
local helpers = require "spec.helpers"
local cjson = require "cjson.safe"

local dp_status_port = helpers.get_available_port()
local cp_status_port = helpers.get_available_port()

for _, strategy in helpers.each_strategy() do

  describe("Hybrid Mode - status ready #" .. strategy, function()

    helpers.get_db_utils(strategy, {
    }) -- runs migrations

    assert(helpers.start_kong({
      role = "data_plane",
      database = "off",
      prefix = "servroot2",
      cluster_cert = "spec/fixtures/kong_clustering.crt",
      cluster_cert_key = "spec/fixtures/kong_clustering.key",
      cluster_control_plane = "127.0.0.1:9005",
      proxy_listen = "127.0.0.1:9002",
  
      status_listen = "127.0.0.1:" .. dp_status_port,
    }))

    -- now dp should be not ready

    describe("status ready endpoint", function()

      it("returns 503 on data plane", function()
        helpers.wait_until(function()
          local http_client = helpers.http_client('127.0.0.1', dp_status_port)

          local res = http_client:send({
            method = "GET",
            path = "/status/ready",
          })

          local status = res and res.status
          http_client:close()
          if status == 503 then
            return true
          end
        end, 5)
      end)
    end)
    
    assert(helpers.start_kong({
        role = "control_plane",
        cluster_cert = "spec/fixtures/kong_clustering.crt",
        cluster_cert_key = "spec/fixtures/kong_clustering.key",
        database = strategy,
        prefix = "servroot",
        cluster_listen = "127.0.0.1:9005",
        nginx_conf = "spec/fixtures/custom_nginx.template",

        status_listen = "127.0.0.1:" .. cp_status_port
    }))

    -- now cp should be ready

    describe("status ready endpoint", function()

      it("returns 200 on control plane", function()
        helpers.wait_until(function()
          local http_client = helpers.http_client('127.0.0.1', cp_status_port)

          local res = http_client:send({
            method = "GET",
            path = "/status/ready",
          })

          local status = res and res.status
          http_client:close()
          if status == 200 then
            return true
          end
        end, 5)
      end)
    end)

    -- now dp receive config from cp, so dp should be ready

    describe("status ready endpoint", function()

      it("returns 200 on data plane", function()
        helpers.wait_until(function()
          local http_client = helpers.http_client('127.0.0.1', dp_status_port)

          local res = http_client:send({
            method = "GET",
            path = "/status/ready",
          })

          local status = res and res.status
          http_client:close()
          if status == 200 then
            return true
          end
        end, 10)
      end)
    end)

    lazy_teardown(function()
        helpers.stop_kong("servroot")
        helpers.stop_kong("servroot2")
    end)
  end)
end
