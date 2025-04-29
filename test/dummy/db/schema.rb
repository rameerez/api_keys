# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema[8.0].define(version: 2025_04_29_150536) do
  create_table "api_keys", force: :cascade do |t|
    t.string "prefix", null: false
    t.string "token_digest", null: false
    t.string "digest_algorithm", null: false
    t.string "last4", limit: 4, null: false
    t.string "name"
    t.string "owner_type"
    t.bigint "owner_id"
    t.json "scopes", default: [], null: false
    t.json "metadata", default: {}, null: false
    t.datetime "expires_at"
    t.datetime "last_used_at"
    t.bigint "requests_count", default: 0, null: false
    t.datetime "revoked_at"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["expires_at"], name: "index_api_keys_on_expires_at"
    t.index ["last4"], name: "index_api_keys_on_last4"
    t.index ["last_used_at"], name: "index_api_keys_on_last_used_at"
    t.index ["owner_id"], name: "index_api_keys_on_owner_id"
    t.index ["owner_type", "owner_id"], name: "index_api_keys_on_owner"
    t.index ["owner_type"], name: "index_api_keys_on_owner_type"
    t.index ["prefix", "digest_algorithm"], name: "index_api_keys_on_prefix_and_digest_algorithm"
    t.index ["prefix"], name: "index_api_keys_on_prefix"
    t.index ["revoked_at"], name: "index_api_keys_on_revoked_at"
    t.index ["token_digest"], name: "index_api_keys_on_token_digest", unique: true
  end

  create_table "users", force: :cascade do |t|
    t.string "email"
    t.string "name"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
  end
end
