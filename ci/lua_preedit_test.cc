#include <gtest/gtest.h>
#include <rime/composition.h>
#include <rime/context.h>
#include <rime/dict/dict_compiler.h>
#include <rime/dict/dictionary.h>
#include <rime/engine.h>
#include <rime/key_event.h>
#include <rime/menu.h>
#include <rime/schema.h>
#include <rime/translator.h>

using namespace rime;

namespace {
const string kSh = "\xe3\x84\x95";
const string kU = "\xe3\x84\xa8";
const string kR = "\xe3\x84\x96";

the<Engine> CreateLuaEngine(bool with_script, bool lua_first = false) {
  auto config = new Config;
  auto processors = New<ConfigList>();
  processors->Append(New<ConfigValue>("speller"));
  config->SetItem("engine/processors", processors);
  auto segmentors = New<ConfigList>();
  segmentors->Append(New<ConfigValue>("abc_segmentor"));
  config->SetItem("engine/segmentors", segmentors);
  auto translators = New<ConfigList>();
  if (with_script && !lua_first)
    translators->Append(New<ConfigValue>("script_translator"));
  translators->Append(New<ConfigValue>("lua_translator@*ci_preedit_smoke"));
  if (with_script && lua_first)
    translators->Append(New<ConfigValue>("script_translator"));
  config->SetItem("engine/translators", translators);
  config->SetString("translator/dictionary", "dictionary_test");
  config->SetItem("translator/enable_user_dict", New<ConfigValue>(false));
  config->SetItem("translator/enable_completion", New<ConfigValue>(false));
  auto rules = New<ConfigList>();
  rules->Append(New<ConfigValue>("xlit/gjb/" + kSh + kU + kR + "/"));
  config->SetItem("translator/preedit_format", rules);
  the<Engine> engine(Engine::Create());
  engine->ApplySchema(new Schema("lua_preedit_test", config));
  return engine;
}

bool TypeLuaInput(Engine* engine, const string& input) {
  for (unsigned char ch : input) {
    if (!engine->ProcessKey(KeyEvent(ch, 0)))
      return false;
  }
  return true;
}
}  // namespace

class LuaPreeditInputTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Registration requires the merged Lua module to have initialized.
    ASSERT_NE(nullptr, Translator::Require("lua_translator"));
    if (!dictionary_ready_) {
      the<Dictionary> dictionary(new Dictionary(
          "dictionary_test", {},
          {New<Table>(path{"dictionary_test.table.bin"})},
          New<Prism>(path{"dictionary_test.prism.bin"})));
      DictCompiler compiler(dictionary.get());
      ASSERT_TRUE(compiler.Compile(path()));
      dictionary_ready_ = true;
    }
  }
  inline static bool dictionary_ready_ = false;
};

TEST_F(LuaPreeditInputTest, LoadedLuaTranslatorProducesAndCommitsCandidate) {
  auto engine = CreateLuaEngine(false);
  ASSERT_TRUE(TypeLuaInput(engine.get(), "lua"));
  auto ctx = engine->context();
  auto candidate = ctx->GetSelectedCandidate();
  ASSERT_TRUE(candidate);
  EXPECT_EQ("lua_smoke", candidate->type());
  EXPECT_EQ("LUA_OK", candidate->text());
  EXPECT_EQ(0U, candidate->start());
  EXPECT_EQ(3U, candidate->end());
  ASSERT_EQ(1U, ctx->composition().back().menu->Prepare(8));
  EXPECT_EQ("lua", ctx->get_property("lua_smoke_done"));
  EXPECT_EQ("lua", ctx->input());
  EXPECT_EQ("LUA_OK", ctx->GetCommitText());
  string committed;
  auto connection = engine->sink().connect(
      [&](const string& text) { committed = text; });
  EXPECT_TRUE(ctx->Commit());
  EXPECT_EQ("LUA_OK", committed);
  connection.disconnect();
}

TEST_F(LuaPreeditInputTest, EmptyLuaQueryPreservesFallbackInBothTranslatorOrders) {
  for (bool lua_first : {false, true}) {
    SCOPED_TRACE(lua_first);
    auto engine = CreateLuaEngine(true, lua_first);
    ASSERT_TRUE(TypeLuaInput(engine.get(), "gjb"));
    auto ctx = engine->context();
    EXPECT_EQ("gjb", ctx->get_property("lua_smoke_done"));
    EXPECT_FALSE(ctx->HasMenu());
    const Preedit preedit = ctx->GetPreedit();
    EXPECT_EQ(kSh + kU + kR, preedit.text);
    EXPECT_EQ(0U, preedit.sel_start);
    EXPECT_EQ(9U, preedit.sel_end);
    EXPECT_EQ(9U, preedit.caret_pos);
    EXPECT_EQ("gjb", ctx->input());
    EXPECT_EQ("gjb", ctx->GetCommitText());

    ctx->set_caret_pos(2);
    EXPECT_EQ("gj", ctx->get_property("lua_smoke_done"));
    EXPECT_FALSE(ctx->HasMenu());
    const Preedit middle = ctx->GetPreedit();
    EXPECT_EQ(kSh + kU + "b", middle.text);
    EXPECT_EQ(0U, middle.sel_start);
    EXPECT_EQ(6U, middle.sel_end);
    EXPECT_EQ(6U, middle.caret_pos);
    EXPECT_EQ(2U, ctx->caret_pos());
    EXPECT_EQ("gjb", ctx->input());
    EXPECT_EQ("gj", ctx->GetCommitText());
  }
}
