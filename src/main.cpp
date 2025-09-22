#include <irods/irods_logger.hpp>
#include <irods/irods_plugin_context.hpp>
#include <irods/irods_re_plugin.hpp>
#include <irods/irods_state_table.h>
#include <irods/rodsError.h>
#include <irods/rodsErrorTable.h>

#include <fmt/format.h>
#include <boost/any.hpp>

#include <list>
#include <string>
#include <string_view>
#include <algorithm>
#include <optional>

#include <sol/sol.hpp>

#include "converter.hpp"

namespace
{
	static sol::bytecode core_file;
	static thread_local sol::state lua_state;
	using log_rule_engine = irods::experimental::log::rule_engine;

	auto get_rei(irods::callback& _effect_handler) -> ruleExecInfo_t&
	{
		ruleExecInfo_t* rei{};
		irods::error result{_effect_handler("unsafe_ms_ctx", &rei)};

		if (!result.ok()) {
			THROW(result.code(), "Failed to get rule execution info");
		}

		return *rei;
	} // get_rei

	//
	// Rule Engine Plugin
	//

	template <typename... Args>
	using operation = std::function<irods::error(irods::default_re_ctx&, Args...)>;

	auto start(irods::default_re_ctx&, const std::string& _instance_name) -> irods::error
	{
		sol::state loader;
		sol::load_result some_script;
		//
		// Initialize the plugin instance here.
		//
		some_script = loader.load_file("/etc/irods/core.lua");
		if (!some_script.valid()) {
			sol::error err{some_script};
			log_rule_engine::error("[{}]: Issue loading script: [{}]", __func__, err.what());
			return ERROR(SYS_INTERNAL_ERR, err.what());
		}
		sol::protected_function code_as_func = some_script;
		core_file = code_as_func.dump();

		// Try to front-load loading of things
		lua_state.open_libraries(sol::lib::base);

		auto res{lua_state.safe_script(core_file.as_string_view(), sol::script_pass_on_error)};

		if (!res.valid()) {
			sol::error error_info{res};
			log_rule_engine::error(
				"[{}]: An error processing the script has occurred: [{}]", __func__, error_info.what());
			return ERROR(SYS_INTERNAL_ERR, error_info.what());
		}

		log_rule_engine::info("[{}]: Rule engine plugin started.", __func__);

		return SUCCESS();
	} // start

	auto stop(irods::default_re_ctx&, const std::string& _instance_name) -> irods::error
	{
		//
		// Shutdown the plugin instance here (i.e. release resources).
		//

		log_rule_engine::info("NOP rule engine plugin stopped [stop].");

		return SUCCESS();
	} // stop

	auto rule_exists(irods::default_re_ctx&, const std::string& _rule_name, bool& _exists) -> irods::error
	{
		//
		// Set "_exists" to true if "_rule_name" is supported by this plugin.
		//

		if (!lua_state[_rule_name].valid()) {
			// log_rule_engine::info("[{}]: Rule [{}] does not exist.", __func__, _rule_name);
			_exists = false;
		}
		else {
			log_rule_engine::info("[{}]: Found rule [{}].", __func__, _rule_name);
			_exists = true;
		}

		return SUCCESS();
	} // rule_exists

	auto list_rules(irods::default_re_ctx&, std::vector<std::string>& _rules) -> irods::error
	{
		//
		// Append all rules supported by this plugin to "_rules".
		//

		log_rule_engine::info("NOP rule engine plugin does not provide any rules [list_rules].");
		lua_state.for_each([&_rules, &func = __func__](const sol::object& key, const sol::object& value) {
			if (sol::type::function == value.get_type()) {
				auto function_name{key.as<std::string>()};
				log_rule_engine::debug("[{}]: Found function [{}].", func, function_name);
				_rules.push_back(function_name);
			}
		});

		return SUCCESS();
	} // list_rules

  template <typename... CapturedArgs>
  struct argsBuilder {
    using CapturedArgsTuple = std::tuple<std::decay_t<CapturedArgs>...>;

	template <typename... Args>
	static auto capture_by_copy(Args&&... args)
	{
	  return std::tuple<std::decay_t<Args>...>(std::forward<Args>(args)...);
	}
    std::tuple<CapturedArgs...> args;

    argsBuilder(CapturedArgs&&... a) : args{a...} {
    }
    template<typename... NewArgs>
    auto operator()(NewArgs&&... b) const {
      auto new_thing{capture_by_copy(b...)};
      auto all_thing{std::tuple_cat(args, std::move(new_thing))};
      return argsBuilder<CapturedArgs..., NewArgs...>(all_thing);
    }
  };
  
	auto exec_rule(irods::default_re_ctx&,
	               const std::string& _rule_name,
	               std::list<boost::any>& _rule_arguments,
	               irods::callback _effect_handler) -> irods::error
	{
		//
		// Process "_rule_name" given "_rule_arguments".
		// Think of this as calling "_rule_name(_rule_arguments_0, _rule_arguments_1, ..., _rule_arguments_N)".
		//

		log_rule_engine::info("[{}]: Trying to run func [{}] from luaville.", __func__, _rule_name);

		argsBuilder thang;
	        for (auto& rule_arg : _rule_arguments) {
		  thang = thang(object_from_any(rule_arg));
		}

		// If we get to `exec_rule(...)`, assume the function exists
		sol::function test_func{lua_state[_rule_name]};
		std::string cool_text{std::apply(test_func, thang.args)};

		log_rule_engine::debug("[{}]: Get back [{}] from [{}].", __func__, cool_text, _rule_name);

		return SUCCESS();
	} // exec_rule

	auto exec_rule_text_impl(std::string_view _rule_text,
	                         MsParamArray* _ms_param_array,
	                         irods::callback _effect_handler) -> irods::error
	{
		log_rule_engine::debug("_rule_text = [{}]", _rule_text);

		// irule <text>
		if (_rule_text.find("@external rule {") != std::string_view::npos) {
			const auto start = _rule_text.find_first_of('{') + 1;
			const auto end = _rule_text.rfind(" }");

			if (end == std::string_view::npos) {
				auto msg = fmt::format("Received malformed rule text. "
				                       "Expected closing curly brace following rule text [{}].",
				                       _rule_text);
				log_rule_engine::error(msg);
				return ERROR(SYS_INVALID_INPUT_PARAM, std::move(msg));
			}

			_rule_text = _rule_text.substr(start, end - start);
		}
		// irule -F <script>
		else if (const auto external_pos = _rule_text.find("@external\n"); external_pos != std::string_view::npos) {
			_rule_text = _rule_text.substr(external_pos + 10);
		}

		log_rule_engine::debug("_rule_text = [{}]", std::string{_rule_text});

		//
		// Process "_rule_text".
		// This handler is triggered by invocations of "irule".
		//

		log_rule_engine::info(
			"NOP rule engine plugin does not provide any rules [exec_rule_text, exec_rule_expression].");

		return SUCCESS();
	} // exec_rule_text_impl
} // anonymous namespace

//
// Plugin Factory
//

using pluggable_rule_engine = irods::pluggable_rule_engine<irods::default_re_ctx>;

extern "C" auto plugin_factory(const std::string& _instance_name, const std::string& _context) -> pluggable_rule_engine*
{
	// clang-format off
	[[maybe_unused]] const auto no_op         = [](auto&&...) { return SUCCESS(); };
	[[maybe_unused]] const auto not_supported = [](auto&&...) { return CODE(SYS_NOT_SUPPORTED); };

	// An adapter that allows exec_rule_text_impl to be used for exec_rule_text operations.
	const auto exec_rule_text_wrapper = [](irods::default_re_ctx& _ctx,
	                                       const std::string& _rule_text,
	                                       msParamArray_t* _ms_params,
	                                       const std::string& _out_desc,
	                                       irods::callback _effect_handler)
	{
		return exec_rule_text_impl(_rule_text, _ms_params, _effect_handler);
	};

	// An adapter that allows exec_rule_text_impl to be used for exec_rule_expression operations.
	const auto exec_rule_expression_wrapper = [](irods::default_re_ctx& _ctx,
	                                             const std::string& _rule_text,
	                                             msParamArray_t* _ms_params,
	                                             irods::callback _effect_handler)
	{
		return exec_rule_text_impl(_rule_text, _ms_params, _effect_handler);
	};
	// clang-format on

	auto* re = new pluggable_rule_engine{_instance_name, _context};

	re->add_operation("start", operation<const std::string&>{start});
	re->add_operation("stop", operation<const std::string&>{stop});
	re->add_operation("rule_exists", operation<const std::string&, bool&>{rule_exists});
	re->add_operation("list_rules", operation<std::vector<std::string>&>{list_rules});
	re->add_operation("exec_rule", operation<const std::string&, std::list<boost::any>&, irods::callback>{exec_rule});

	// Replace the "exec_rule_*_wrapper" arguments with the "not_supported" lambda if support for
	// "irule" is not needed.
	re->add_operation(
		"exec_rule_text",
		operation<const std::string&, msParamArray_t*, const std::string&, irods::callback>{exec_rule_text_wrapper});
	re->add_operation("exec_rule_expression",
	                  operation<const std::string&, msParamArray_t*, irods::callback>{exec_rule_expression_wrapper});

	return re;
} // plugin_factory
