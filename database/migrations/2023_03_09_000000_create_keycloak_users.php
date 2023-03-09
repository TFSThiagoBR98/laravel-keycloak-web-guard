<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        if (Schema::hasTable('users')) {
            if (!Schema::hasColumn('users', 'extra_attributes')) {
                Schema::table('users', function (Blueprint $table) {
                    $table->schemalessAttributes('extra_attributes');
                });
            }
        } else {
            Schema::create('users', function (Blueprint $table) {
                $table->uuid('id');
                $table->string('name');
                $table->string('email')->unique();
                $table->schemalessAttributes('extra_attributes');
                $table->timestamps();
            });
        }
        
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        if (Schema::hasColumn('users', 'extra_attributes')) {
            Schema::table('users', function (Blueprint $table) {
                $table->removeColumn('extra_attributes');
            });
        }
    }
};