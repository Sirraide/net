#include <net/execution/exec_context.hh>
#include <benchmark/benchmark.h>

FILE *f;

static void test(benchmark::State& state) {
    net::execution_context ctx;
    f = fopen("/dev/null", "w");
    defer { fclose(f); };

    for (auto _ : state) {
        for (size_t i = 0; i < 10000; i++) {
            ctx.add_task([]{
                fmt::print(f, "{}\n", 1);
            });
        }
        net::stop_flag stop;
        ctx.flush_and_stop(stop);
    }
}

static void control(benchmark::State& state) {
    f = fopen("/dev/null", "w");
    defer { fclose(f); };

    for (auto _ : state) {
        for (size_t i = 0; i < 10000; i++) {
            fmt::print(f, "{}\n", 1);
        }
    }
}

BENCHMARK(test);
BENCHMARK(control);

BENCHMARK_MAIN();