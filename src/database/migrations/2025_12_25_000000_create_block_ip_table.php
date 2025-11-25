<?php

// phpcs:ignoreFile

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use OhSeeSoftware\LaravelServerAnalytics\Facades\ServerAnalytics;

class CreateBlockTable extends Migration
{
    public function up()
    {
        Schema::create('analytics_block_ip', function (Blueprint $table) {
            $table->bigIncrements('id');
            $table->timestamps();
            $table->string('ip')->index();
        });
    }
}
