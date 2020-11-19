std::vector<float> h_X(length,xval);
    std::vector<float> h_Y(length,yval);
    std::vector<float> h_Z(length,zval);

    try {

        sycl::queue q(sycl::default_selector{});

        const float A(aval);

        sycl::buffer<float,1> d_X { h_X.data(), sycl::range<1>(h_X.size()) };
        sycl::buffer<float,1> d_Y { h_Y.data(), sycl::range<1>(h_Y.size()) };
        sycl::buffer<float,1> d_Z { h_Z.data(), sycl::range<1>(h_Z.size()) };

        q.submit([&](sycl::handler& h) {

            auto X = d_X.template get_access<sycl::access::mode::read>(h);
            auto Y = d_Y.template get_access<sycl::access::mode::read>(h);
            auto Z = d_Z.template get_access<sycl::access::mode::read_write>(h);

            h.parallel_for<class nstream>( sycl::range<1>{length}, [=] (sycl::id<1> it) {
                const int i = it[0];
                Z[i] += A * X[i] + Y[i];
            });
          });
          q.wait();
    }
    catch (sycl::exception & e) {
        std::cout << e.what() << std::endl;
        std::abort();
    }